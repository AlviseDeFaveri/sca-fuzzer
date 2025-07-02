"""
File: Structured parsing for revizor's debug traces.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""

from typing import Any, Dict, Optional

from rvzr.model_dynamorio.trace_decoder import DebugTraceEntryType


# Entries that are relevant to an instruction.
_INST_ENTRIES = [
    DebugTraceEntryType.ENTRY_REG_DUMP,
    DebugTraceEntryType.ENTRY_READ,
    DebugTraceEntryType.ENTRY_WRITE,
    DebugTraceEntryType.ENTRY_LOC,
    DebugTraceEntryType.ENTRY_REG_DUMP_EXTENDED,
    DebugTraceEntryType.ENTRY_USE_DEF,
]
# Entries that indicate the instruction information has ended.
_INST_TERMINATORS = [
    DebugTraceEntryType.ENTRY_REG_DUMP,
    DebugTraceEntryType.ENTRY_EOT,
    DebugTraceEntryType.ENTRY_EXCEPTION,
    DebugTraceEntryType.ENTRY_CHECKPOINT,
    DebugTraceEntryType.ENTRY_ROLLBACK,
    DebugTraceEntryType.ENTRY_ROLLBACK_STORE,
]


class ParsedInst:
    """
    Class holding all the information related to a specific instruction that can be parsed from
    a debug trace.
    """
    entries: list
    start: int
    end: int
    loc: str
    code: str
    regs: Dict[int, int]

    def __init__(self) -> None:
        self.entries = {}
        self.regs = {}

    def digest(self, entry: Any) -> bool:
        """
        Add information coming from one line of the debug trace to this instruction.
        Returns false if the entry was not "digested", i.e. it was not added to the instruction.
        """
        t = DebugTraceEntryType(entry.type)

        if t in _INST_ENTRIES:
            # Collect all reads and writes in two lists.
            if t in [DebugTraceEntryType.ENTRY_READ, DebugTraceEntryType.ENTRY_WRITE]:
                if t not in self.entries.keys():
                    # Create the list of reads/writes if they are not there
                    self.entries[t] = []
                self.entries[t].append(entry)
            else:
                # Simply add the entry in a map
                self.entries[t] = entry

            # Parse registers
            if t == DebugTraceEntryType.ENTRY_REG_DUMP:
                self.regs["RAX"] = entry.regs.xax
                self.regs["RBX"] = entry.regs.xbx
                self.regs["RCX"] = entry.regs.xcx
                self.regs["RDX"] = entry.regs.xdx
                self.regs["RSI"] = entry.regs.xsi
                self.regs["RDI"] = entry.regs.xdi
            elif t == DebugTraceEntryType.ENTRY_REG_DUMP_EXTENDED:
                self.regs["RSP"] = entry.regs_2.rsp
                self.regs["RBP"] = entry.regs_2.rbp
                self.regs["R8"] = entry.regs_2.r8
                self.regs["R9"] = entry.regs_2.r9
                self.regs["R10"] = entry.regs_2.r10
                self.regs["R11"] = entry.regs_2.r11

            return True

        return False

    def get_pc(self) -> int:
        """
        Return the PC of this instruction.
        """
        return self.entries[DebugTraceEntryType.ENTRY_REG_DUMP].regs.pc

    def get_reg_uses(self) -> list[int]:
        """
        Return the ids of the registers used directly by this instruction.
        """
        return [x for x in self.entries[DebugTraceEntryType.ENTRY_USE_DEF].def_use.reg_use if x != 0]

    def get_mem_uses(self) -> list[int]:
        """
        Return the ids of the registers used to compute a memory address in instruction.
        """
        return [x for x in self.entries[DebugTraceEntryType.ENTRY_USE_DEF].def_use.mem_use if x != 0]

    def get_mem_reads(self) -> list[tuple[int, int]]:
        """
        Return a list of <address,value> pairs for each memory location read by this instruction.
        """
        if DebugTraceEntryType.ENTRY_READ not in self.entries:
            return []
        return [(x.mem.address, x.mem.value) for x in self.entries[DebugTraceEntryType.ENTRY_READ]]

    def get_loc(self) -> str:
        """
        Return location string
        """
        if DebugTraceEntryType.ENTRY_LOC in self.entries:
            loc_info = self.entries[DebugTraceEntryType.ENTRY_LOC].loc
            module = ''.join([x.decode('utf-8') for x in loc_info.module_name])
            return module + '+' + str(loc_info.offset)
        return 'unknown+0x0'


class TraceState:
    """
    Associates a trace with a cursor that is aware of the currently-parsed instruction.
    This avoids grouping all the entries into parsed instructions, allowing to create ParsedInst
    object on-demand.
    """
    trace: list[Any]
    cur_idx: int
    cur_entry: Any
    cur_inst: ParsedInst

    def __init__(self, trace: list[Any]) -> None:
        self.trace = trace
        self.cur_idx = 0
        self.cur_entry = self.trace[0]
        self.cur_inst = ParsedInst()

    def seek(self, lineno: int) -> None:
        """
        Move cursor to a specific line of the trace.
        """
        self.cur_idx = lineno
        self.cur_entry = self.trace[self.cur_idx]

    def _prev_entry(self) -> None:
        """
        Move cursor to previous trace line.
        """
        self.seek(self.cur_idx - 1)

    def _next_entry(self)-> None:
        """
        Move cursor to next trace line.
        """
        self.seek(self.cur_idx + 1)

    def prev_entry(self) -> None:
        """
        Move cursor to previous trace line in the same speculative window
        (skips nested speculation window that happened before the current entry).
        """
        cur_nesting = self.cur_entry.nesting_level
        self._prev_entry()
        while self.cur_entry.nesting_level > cur_nesting:
             self._prev_entry()

    def next_entry(self) -> None:
        """
        Move cursor to next trace line in the same speculative window
        (skips nested speculation window that happened after the current entry).
        """
        cur_nesting = self.cur_entry.nesting_level
        self._next_entry()
        while self.cur_entry.nesting_level > cur_nesting:
             self._next_entry()

    def parse_current(self) -> ParsedInst:
        """
        Finds what instruction is related to the current line and parses all relevant information
        for that instruction.
        """
        # Find the start of the instruction
        while DebugTraceEntryType(self.cur_entry.type) != DebugTraceEntryType.ENTRY_REG_DUMP:
            self.prev_entry()

        first_line = self.cur_idx

        # Digest first entry
        self.cur_inst = ParsedInst()
        self.cur_inst.digest(self.cur_entry)
        self.next_entry()

        # Digest other entries until we find a terminator
        while DebugTraceEntryType(self.cur_entry.type) not in _INST_TERMINATORS:
            self.cur_inst.digest(self.cur_entry)
            self.next_entry()

        # Move back to the first entry
        self.seek(first_line)
        return self.cur_inst

    def find_last_def(self, val: int, until: int, mem: bool=False) -> tuple[Optional[int], Optional[ParsedInst]]:
        """
        Find the most recent instruction in the trace before `until` that wrote to `val`.
        `val` is a register id if `mem` is false, otherwise it's an address.
        Returns a parsed instruction and the corresponding line, or <None, None> if no previous
        definition is found.
        """
        cur_nesting = self.trace[until].nesting_level
        found = None

        # Start from `until`
        idx = until
        while idx > 0:
            # Go to previous line
            idx -= 1
            e = self.trace[idx]
            # Only  consider entries of the same spec window or architectural entries
            if e.nesting_level > cur_nesting:
                continue
            cur_nesting = e.nesting_level

            # If we're looking for memory defs, check memory stores.
            if mem and DebugTraceEntryType(e.type) == DebugTraceEntryType.ENTRY_WRITE:
                if val == e.mem.address:
                    return idx, e
            # If we're looking for register defs, check USE_DEF entries.
            elif not mem and DebugTraceEntryType(e.type) == DebugTraceEntryType.ENTRY_USE_DEF:
                if val in e.def_use.reg_def:
                    found = e
                    return idx, e

        # Reached the start of the trace.
        return None, None
