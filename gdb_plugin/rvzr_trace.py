from typing import Any, Optional
from rvzr.model_dynamorio.trace_decoder import TraceDecoder, DebugTraceEntryType
from utils import Color, getc
from debug_symbols import SymbolServer

# Classes of entries
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

# where to read symbols from
_glob_sym_server = None

class ParsedInst:
    entries: list
    start: int
    end: int

    def __init__(self) -> None:
        self.entries = {}

    def digest(self, entry: Any) -> bool:
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

    def get_pc(self) -> int:
        return self.entries[DebugTraceEntryType.ENTRY_REG_DUMP].regs.pc

    def get_reg_uses(self) -> list[int]:
        return [x for x in self.entries[DebugTraceEntryType.ENTRY_USE_DEF].def_use.reg_use if x != 0]

    def get_mem_uses(self) -> list[int]:
        return [x for x in self.entries[DebugTraceEntryType.ENTRY_USE_DEF].def_use.mem_use if x != 0]

    def get_mem_reads(self) -> list[int]:
        if DebugTraceEntryType.ENTRY_READ not in self.entries:
            return []
        return [x.mem.address for x in self.entries[DebugTraceEntryType.ENTRY_READ]]

    def get_loc(self) -> str:
        loc = _glob_sym_server.get_location(self.get_pc())
        if loc is None:
            module_name = ''.join([x.decode('utf-8') for x in self.entries[DebugTraceEntryType.ENTRY_LOC].loc.module_name])[:-1]
            offset = hex(self.entries[DebugTraceEntryType.ENTRY_LOC].loc.offset)
            loc = f"  {module_name}+{offset}"
        return loc

    def get_nesting_level(self) -> int:
        return self.entries[DebugTraceEntryType.ENTRY_REG_DUMP].nesting_level

    def get_short_descr(self, idx) -> str:
        pc_expr = '[ARCH] ' if self.get_nesting_level() == 0 else '[SPEC] '
        pc_expr += hex(self.get_pc())
        pc = getc(Color.CYAN, pc_expr)
        loc = getc(Color.PURPLE, self.get_loc())
        line = getc(Color.GREEN, idx)
        return f"{pc} (line {line})  @  {loc}"


class TraceState:
    def __init__(self, trace_file: str, symbol_server: SymbolServer) -> None:
        self.decoder = TraceDecoder()
        _, dbg_traces = self.decoder.decode_trace_file(trace_file)
        assert len(dbg_traces) == 1
        dbg_trace = dbg_traces[0]

        self.trace = dbg_trace
        global _glob_sym_server
        _glob_sym_server = symbol_server

        self.cur_idx = 0
        self.cur_entry = ""
        self.cur_inst = ParsedInst()

    def seek(self, lineno) -> None:
        self.cur_idx = lineno
        self.cur_entry = self.trace[self.cur_idx]

    def _prev_entry(self) -> None:
        self.seek(self.cur_idx - 1)

    def _next_entry(self)-> None:
        self.seek(self.cur_idx + 1)

    def prev_entry(self) -> None:
        cur_nesting = self.cur_entry.nesting_level
        self._prev_entry()
        while self.cur_entry.nesting_level > cur_nesting:
             self._prev_entry()

    def next_entry(self) -> None:
        cur_nesting = self.cur_entry.nesting_level
        self._next_entry()
        while self.cur_entry.nesting_level > cur_nesting:
             self._next_entry()

    def parse_current(self) -> ParsedInst:
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

    def find_last_def(self, val: int, until: int, mem: bool =False) -> tuple[Optional[int], Optional[ParsedInst]]:
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
