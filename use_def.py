import sys
import os
from elftools.elf.elffile import ELFFile

from rvzr.model_dynamorio.trace_decoder import TraceDecoder, DebugTraceEntryType
from utils import REGS, OPMASKS, Color, getc

from pygdbmi.gdbcontroller import GdbController
from pprint import pprint

_INST_ENTRIES = [
    DebugTraceEntryType.ENTRY_REG_DUMP,
    DebugTraceEntryType.ENTRY_READ,
    DebugTraceEntryType.ENTRY_WRITE,
    DebugTraceEntryType.ENTRY_LOC,
    DebugTraceEntryType.ENTRY_REG_DUMP_EXTENDED,
    DebugTraceEntryType.ENTRY_USE_DEF,
]

_INST_TERMINATORS = [
    DebugTraceEntryType.ENTRY_REG_DUMP,
    DebugTraceEntryType.ENTRY_EOT,
    DebugTraceEntryType.ENTRY_EXCEPTION,
    DebugTraceEntryType.ENTRY_CHECKPOINT,
    DebugTraceEntryType.ENTRY_ROLLBACK,
    DebugTraceEntryType.ENTRY_ROLLBACK_STORE,
]

_DONT_FOLLOW = OPMASKS # + ["RSP", "RBP"]

_KNOWN_SYMS = [
]

_DECLASSIFIED = [
    "lib/aes-xmm.c:345",
]

_KEY = [
    "lib/aes-key.c:224",
    "lib/aes-key.c:225",
    "lib/aes-key.c:40",
]

_glob_gdb_server = None
_glob_visited = []

def is_known_sym(address):
    for name, start, sz in _KNOWN_SYMS:
            if address >= start and address < start + sz:
                return name
    return None

# class DebugServer:
#     def __init__(self, binary: str):
#         # Start gdb process
#         self.gdbmi = GdbController()
#         # Load binary
#         _ = self.gdbmi.write(f'file {binary}')

#     def get_location(self, address: int):
#         # Try to get source location
#         response = self.gdbmi.write(f'info line *{hex(address)}')
#         payload = response[1]["payload"]
#         # If not available, get at least function name
#         if "No line number" in payload:
#             response = self.gdbmi.write(f'info sym {hex(address)}')
#             payload = response[1]["payload"]
#             # Format as <module>+<offset>
#             splitted = payload.strip().split(" ")
#             payload = splitted[0] + "+" + splitted[2]

#         else:
#             # Format as <file>:<line>
#             splitted = payload.split(" ")
#             payload = splitted[3].replace("\"","") + ":" + splitted[1]

#         return payload.strip()

class DebugServer:
    def __init__(self, binary: str):
        with open(binary, "rb") as f:
            self._elf_data = ELFFile(f)
            self.dwarf_info = self._elf_data.get_dwarf_info()
            # Start gdb process
            self.gdbmi = GdbController()
            # Load binary
            _ = self.gdbmi.write(f'file {binary}')

    def get_location(self, address: int):
        # Go over all the line programs in the DWARF information, looking for
        # one that describes the given address.
        for CU in self.dwarf_info.iter_CUs():
            # First, look at line programs to find the file/line for the address
            line = self.dwarf_info.line_program_for_CU(CU)
            if not line:
                continue
            delta = 1 if line.header.version < 5 else 0
            prevstate = None
            for entry in line.get_entries():
                # We're interested in those entries where a new state is assigned
                if entry.state is None:
                    continue
                # Looking for a range of addresses in two consecutive states that
                # contain the required address.
                if prevstate and prevstate.address <= address < entry.state.address:
                    filename = line['file_entry'][prevstate.file - delta].name.decode()
                    line = prevstate.line
                    return f"{filename}:{line}"
                if entry.state.end_sequence:
                    # For the state with `end_sequence`, `address` means the address
                    # of the first byte after the target machine instruction
                    # sequence and other information is meaningless. We clear
                    # prevstate so that it's not used in the next iteration. Address
                    # info is used in the above comparison to see if we need to use
                    # the line information for the prevstate.
                    prevstate = None
                else:
                    prevstate = entry.state

        # if we're here, we didn't find a symbol - use the slow gdb way
        response = self.gdbmi.write(f'info sym {hex(address)}')
        payload = response[1]["payload"]
        # Format as <module>+<offset>
        splitted = payload.strip().split(" ")
        payload = splitted[0] + "+" + splitted[2]
        return payload


class ParsedInst:
    entries: list

    def __init__(self) -> None:
        self.entries = {}

    def digest(self, entry) -> bool:
        t = DebugTraceEntryType(entry.type)
        if t in _INST_ENTRIES:
            if t in [DebugTraceEntryType.ENTRY_READ, DebugTraceEntryType.ENTRY_WRITE]:
                # Append memory entries
                if t not in self.entries.keys():
                    self.entries[t] = []
                self.entries[t].append(entry)
            else:
                self.entries[t] = entry
            return True

        return False

    def get_pc(self):
        return self.entries[DebugTraceEntryType.ENTRY_REG_DUMP].regs.pc

    def get_reg_uses(self):
        return [x for x in self.entries[DebugTraceEntryType.ENTRY_USE_DEF].def_use.reg_use if x != 0]

    def get_mem_uses(self):
        return [x for x in self.entries[DebugTraceEntryType.ENTRY_USE_DEF].def_use.mem_use if x != 0]

    def get_mem_reads(self):
        if DebugTraceEntryType.ENTRY_READ not in self.entries:
            return []
        return [x.mem.address for x in self.entries[DebugTraceEntryType.ENTRY_READ]]

    def get_loc(self):
        return _glob_gdb_server.get_location(self.get_pc())

    def get_nesting_level(self):
        return self.entries[DebugTraceEntryType.ENTRY_REG_DUMP].nesting_level

    def get_short_descr(self, idx):
        pc_expr = '[ARCH] ' if self.get_nesting_level() == 0 else '[SPEC] '
        pc_expr += hex(self.get_pc())
        pc = getc(Color.CYAN, pc_expr)
        loc = getc(Color.PURPLE, self.get_loc())
        line = getc(Color.GREEN, idx)
        return f"{pc} (line {line})  @  {loc}"


class TraceState:
    def __init__(self, trace):
        self.trace = trace

        self.cur_idx = 0
        self.cur_entry = ""
        self.cur_inst = ParsedInst()

    def seek(self, lineno):
        self.cur_idx = lineno
        self.cur_entry = self.trace[self.cur_idx]

    def _prev_entry(self):
        self.seek(self.cur_idx - 1)

    def _next_entry(self):
        self.seek(self.cur_idx + 1)

    def prev_entry(self):
        cur_nesting = self.cur_entry.nesting_level
        self._prev_entry()
        while self.cur_entry.nesting_level > cur_nesting:
             self._prev_entry()

    def next_entry(self):
        cur_nesting = self.cur_entry.nesting_level
        self._next_entry()
        while self.cur_entry.nesting_level > cur_nesting:
             self._next_entry()

    def parse_current(self):
        # Seek the start of the instruction
        while DebugTraceEntryType(self.cur_entry.type) != DebugTraceEntryType.ENTRY_REG_DUMP:
            self.prev_entry()

        first_inst = self.cur_idx

        # Digest first entry
        self.cur_inst = ParsedInst()
        self.cur_inst.digest(self.cur_entry)
        self.next_entry()

        # Digest other entries
        while DebugTraceEntryType(self.cur_entry.type) not in _INST_TERMINATORS:
            self.cur_inst.digest(self.cur_entry)
            self.next_entry()

        self.seek(first_inst)

        return self.cur_inst

    def find_last_def(self, val, until, mem=False):
        idx = until
        cur_nesting = self.trace[until].nesting_level

        found = None

        while idx > 0:
            idx -= 1
            e = self.trace[idx]
            # Only  consider entries of the same spec window or architectural entries
            if e.nesting_level > cur_nesting:
                continue
            cur_nesting = e.nesting_level

            if mem:
                if DebugTraceEntryType(e.type) == DebugTraceEntryType.ENTRY_WRITE:
                    if val == e.mem.address:
                        found = e
                        break
            else:
                if DebugTraceEntryType(e.type) == DebugTraceEntryType.ENTRY_USE_DEF:
                    if val in e.def_use.reg_def:
                        found = e
                        break

        if found is None:
            return None, None
        return idx, found


def follow_def_use_chain(tracer, idx, prefix, t):
    if idx is None:
        print(f"{prefix}{getc(Color.RED, '---END--- Hit top!')} First use of {t}")
        return []

    tracer.seek(idx)
    cur_inst = tracer.parse_current()

    if any(cur_inst.get_loc().endswith(x) for x in _DECLASSIFIED):
        print(f"{prefix}{getc(Color.YELLOW, '---END--- Found declassified!')} {t} defined by {cur_inst.get_short_descr(idx)}")
        return []

    if any(cur_inst.get_loc().endswith(x) for x in _KEY):
        print(f"{prefix}{getc(Color.RED, '---END--- Found key!')} {t} defined by {cur_inst.get_short_descr(idx)}")
        return []

    print(f"{prefix} using {t} defined by {cur_inst.get_short_descr(idx)}")
    defs = []

    for address in cur_inst.get_mem_reads():
        name = is_known_sym(address)
        if name is not None:
            print(''.join(prefix[:-2]) + '    ' + ''.join(prefix[-2:]) + getc(Color.YELLOW, f'---END--- Hit known input: {name}'))
            continue

        next_idx, e = tracer.find_last_def(address, until=idx, mem=True)
        defs.append((next_idx, getc(Color.BLUE, hex(address))))

    for reg in cur_inst.get_reg_uses():
        if REGS[reg] in _DONT_FOLLOW:
            continue
        next_idx, e = tracer.find_last_def(reg, until=idx, mem=False)
        defs.append((next_idx, getc(Color.BLUE, REGS[reg])))

    return defs


def follow_def_use_chain_recursive(vals, prefix=""):
    idx = 0
    for v, s in vals:
        if v in _glob_visited:
            print(prefix + "    └─ Skipping (already visited)")
            continue
        if v != None:
            _glob_visited.append(v)

        if idx == len(vals) - 1:
            cur_prefix = prefix + "    └─"
        else:
            cur_prefix = prefix + "    ├─"

        next_list = follow_def_use_chain(tracer, v, cur_prefix, s)
        if idx == len(vals) - 1:
            next_prefix = prefix + "     "
        else:
            next_prefix = prefix + "    │"

        follow_def_use_chain_recursive(next_list, next_prefix)
        idx += 1


if __name__ == '__main__':
    if len(sys.argv) != 5:
        print(f"Usage {sys.argv[0]} <TRACE_FILE> <LINE> <binary> <known_syms>")
        sys.exit(1)
    trace_file = sys.argv[1]
    line_no = int(sys.argv[2])
    binary_path = sys.argv[3]
    known_syms_file = sys.argv[4]

    print(f"Reading known syms {known_syms_file}...")
    with open(known_syms_file, "r") as f:
        for l in f:
            splitted = l.split(" ")
            _KNOWN_SYMS.append((splitted[0], int(splitted[1], 16), int(splitted[2], 16)))

    print(f"Reading symbols for {binary_path}...")
    _glob_gdb_server = DebugServer(binary_path)

    print(f"Decoding trace file {trace_file}...")
    decoder = TraceDecoder()
    _, dbg_traces = decoder.decode_trace_file(trace_file)
    assert len(dbg_traces) == 1
    dbg_trace = dbg_traces[0]

    # Parse current instruction
    tracer = TraceState(dbg_trace)
    tracer.seek(line_no)
    start_inst = tracer.parse_current()

    # Assume data violation: get all MEM_USES
    print(f"Starting from {hex(start_inst.get_pc())} (line {tracer.cur_idx}) {getc(Color.PURPLE, start_inst.get_loc())}")
    print(f"Mem uses: {[REGS[x] + ', ' for x in start_inst.get_mem_uses()]}")
    # visit_stack = []
    # for reg in start_inst.get_mem_uses():
    #     idx, _ = tracer.find_last_def(reg, until=line_no, mem=False)
    #     visit_stack.append((idx, "", REGS[reg]))

    # prefix = "   │"
    # while len(visit_stack) > 0:
    #     (cur, prefix, t) = visit_stack.pop()
    #     next_list = get_defs_of_uses(tracer, cur, prefix + "    ", t)

    #     if len(next_list) == 0:
    #         continue
    #     if len(next_list) == 1:
    #         n, s = next_list[0]
    #         visit_stack.append((n, prefix + "     ", s))
    #         print(f"{n} has one successor")

    #     else:
    #         for n, s in next_list:
    #             visit_stack.append((n, prefix + "    │", s))
    #         print(f"{n} has multiple successors")

    init = [(tracer.find_last_def(x, until=line_no, mem=False)[0], REGS[x]) for x in start_inst.get_mem_uses()]
    follow_def_use_chain_recursive(init)
