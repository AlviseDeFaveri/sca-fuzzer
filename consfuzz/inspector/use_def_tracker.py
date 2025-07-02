"""
File: Implementation of differential origin tracking for leaked values using use-def chains.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""

from typing import Any, Dict, Optional
from enum import Enum

from .regs import REGS, strip_alias, init_reg_map
from .rvzr_trace import TraceState, ParsedInst

# FIXME!!!!!!!!!!!!!!!!!!!!!!
from .utils import Color, getc
from .symbol_server import SymbolServer
from .config import Config


# ------------------------------------------------------------------------------
# Local Types
# ------------------------------------------------------------------------------

class UseType(Enum):
    """
    Indicates a register or memory use.
    """
    MEM = 0
    REG = 1

# Values used by an instruction.
UsesDict = Dict[UseType, Dict[int, int]]
# List of values for the same use across different traces.
MergedUsesDict = Dict[UseType, Dict[int, list[int]]]

def _merge_uses(uses_dicts: list[UsesDict]) -> MergedUsesDict:
    """
    Merge uses from multiple traces.
    This will return a dictionary that has as keys the union of all the keys (sorted by type)
    and as values an array of values where each position corresponds to a separate trace.
    If a use is not present in one of the traces, it's corresponding value in the array is None.
    """
    merged = {UseType.MEM : {}, UseType.REG: {}}
    total = len(uses_dicts)

    for idx, uses in enumerate(uses_dicts):
        for use_type, use_dict in uses.items():
            for addr, val in use_dict.items():
                if addr not in merged[use_type].keys():
                    # If there's no entry, create a list as long as the number of dicts to merge
                    merged[use_type][addr] = [None]*total
                # Add the value at the index corresponding to the current dict being merged
                merged[use_type][addr][idx] = val

    return merged


class TraceBundle:
    """
    Hold the state of a trace together with what use is currently being inspected.
    """
    tracer: TraceState
    line: Optional[int]
    val_name: str

    def __init__(self, tracer: TraceState, line: Optional[int], val_name: str) -> None:
        self.tracer = tracer
        self.line = line
        self.val_name = val_name

    @classmethod
    def from_trace(cls, trace: list[Any], line: int) -> "TraceBundle":
        """
        Create a TraceBundle from trace + line (used to create the initial state).
        """
        tracer = TraceState(trace)
        tracer.seek(line)
        line = tracer.cur_idx

        return TraceBundle(tracer, line, "")

    def update_line(self, line: int) -> None:
        """
        Update the tracked instruction line for this bundle.
        """
        self.tracer.seek(line)
        self.line = line



class DifferentialTraceState:
    """
    Hold the state of multiple traces together (for differential analysis).
    """
    states: list[TraceBundle]

    def __init__(self, states: list[TraceBundle]) -> None:
        self.states = states


# ------------------------------------------------------------------------------
# Tracker implementation
# ------------------------------------------------------------------------------

class UseDefTracker:
    """
    Class that implements reverse use-def exploration for multiple
    traces at a time.
    """
    _visited: list[list[int, int]]
    _out_file: str
    _symbol_server = SymbolServer

    def __init__(self, out_file: str, symbol_server: SymbolServer, config: Config) -> None:
        self._out_file = out_file
        self._symbol_server = symbol_server
        self._visited = []

        # Setup configuration
        Config.init(config)
        self._out_file = open(out_file, "w")

        # Initialize the list of registers
        init_reg_map()

    def _print(self, x: Any) -> None:
        """
        Print to the selected out file.
        """
        print(x, file=self._out_file)

    def _get_loc(self, instr: ParsedInst) -> str:
        """
        Return a formatted string representing the source location of an instruction.
        """
        loc = self._symbol_server.get_location(instr.get_pc())
        if loc is None:
            return instr.get_loc()
        return loc

    def _get_short_descr(self, instr: ParsedInst, line: int) -> str:
        """
        Return a formatted string representing an instruction in the trace.
        """
        return f"{hex(instr.get_pc())} (line: {line})   {self._get_loc(instr)}"

    def _check_if_sink(self, tracer: TraceState, line: Optional[int], prefix: str, t: str) -> Optional[ParsedInst]:
        """
        Check if a line in the trace contains an instruction and, if so, check
        if it's a taint sink and print it.
        Return the current instruction (or 'None' if there's none at the given line).
        """
        # Empty line number means we reached the beginning of the file
        if line is None:
            self._print(f"{prefix}{getc(Color.RED, '─END─ Hit top!')} First use of {t} in the trace")
            return None

        tracer.seek(line)
        cur_inst = tracer.parse_current()

        # String-based matching for sinks
        # TODO: We can implement more refined logic here, e.g. we can add a declassification
        # function inside of the binary and match it here.
        loc = self._get_loc(cur_inst)
        if any(loc.endswith(x) for x in Config.get().declassified):
            self._print(f"{prefix}{getc(Color.YELLOW, '─END─ Found declassified!')} {t} defined by {self._get_short_descr(cur_inst, line)}")
            return None

        return cur_inst

    def _get_uses(self, cur_inst: ParsedInst, prefix: str, regs: bool, mem: bool) -> UsesDict:
        """
        Get a dictionary of used registers/memory locations for an instruction.
        """
        uses = {UseType.MEM : {}, UseType.REG: {}}
        #  Mem uses
        if mem:
            for address, val in cur_inst.get_mem_reads():
                # If it's an annotated region of memory, print the annotation and don't explore
                # further.
                # TODO: Implement a better way of annotating memory regions.
                name, offset = Config.get_sym_annotation(address)
                if name is not None:
                    # Indent to indicate end of this path.
                    prefix = ''.join(prefix[:-2]) + '    ' + ''.join(prefix[-2:])
                    self._print(prefix  + getc(Color.YELLOW, f'─END─ Hit known input: {name}+{hex(offset)}'))
                    continue

                # Othewise, save address <--> value in dictionary.
                uses[UseType.MEM][address] = val
        # Reg uses
        if regs:
            for reg_id in cur_inst.get_reg_uses():
                reg_name = strip_alias(REGS[reg_id])
                # Skip registers explicitly marked as no-follow.
                # NOTE: For now we cut exploration on some registers that are not logged by the
                # tracer (e.g. Kx AVX registers) that we know are not interesting.
                if reg_name in Config.get().dont_follow:
                    continue
                # Try to find the value of the register, if it's among the ones logged by the tracer.
                # NOTE: XMM and other special registers are never logged by the debug tracer, but we
                # still follow them.
                reg_val = None
                if reg_name in cur_inst.regs.keys():
                    reg_val = cur_inst.regs[reg_name]
                # Save reg_id <--> reg value in the dictionary
                uses[UseType.REG][reg_id] = reg_val

        return uses

    def _get_defs(self, uses: MergedUsesDict, cur_state: DifferentialTraceState) -> list[DifferentialTraceState]:
        """
        For each use in `uses`, find the trace line corresponding to the last definition of that
        register or memory location in all the traces of `cur_state`.
        """
        defs = []

        # Mem defs
        for addr, _ in uses[UseType.MEM].items():
            next_states = []
            # Get last def of current address for all traces.
            for s in cur_state.states:
                def_line, _ = s.tracer.find_last_def(addr, until=s.line, mem=True)
                next_states.append(TraceBundle(s.tracer, def_line, getc(Color.BLUE, hex(addr))))
            # Add a new parent state that points to the def of the current use for all traces.
            defs.append(DifferentialTraceState(next_states))

        # Reg defs
        for reg, _ in uses[UseType.REG].items():
            # Skip registers explicitly marked as no-follow.
            if REGS[reg] in Config.get().dont_follow:
                continue

            next_states = []
            # Get def of current register for all traces.
            for s in cur_state.states:
                def_line, _ = s.tracer.find_last_def(reg, until=s.line, mem=False)
                next_states.append(TraceBundle(s.tracer, def_line, getc(Color.BLUE, REGS[reg])))
            # Add a new parent state that points to the def of the current use for all traces.
            defs.append(DifferentialTraceState(next_states))

        return defs

    def _filter_differential(self, merged: MergedUsesDict, prefix: str) -> MergedUsesDict:
        """
        Filter out values that are the same in all differential traces.
        """
        to_remove = {UseType.MEM: [], UseType.REG: []}

        for use_type, use_dict in merged.items():
            for addr, vals in use_dict.items():
                val_str = hex(addr) if use_type == UseType.MEM else REGS[addr]
                if all(v is None for v in vals):
                    # If the corresponding register has an unknown value for all traces,
                    # it means it's not logged. We follow it by default.
                    # print(f"{prefix} Unknown value, visiting...")
                    pass
                elif any(v is None for v in vals):
                    # If a value is only used in some of the traces, we can't continue differentially:
                    # stop backwards tracking.
                    self._print(f"{prefix} [INFO] {val_str} Is not used in some traces, ignoring")
                    to_remove[use_type].append(addr)
                elif all(v == vals[0] for v in vals):
                    # If all the traces agree on a value, we can skip tracking.
                    self._print(f"{prefix} [INFO] {val_str} Has same value in both traces, skipping")
                    to_remove[use_type].append(addr)

        # Remove all entries that were filtered out by our analysis.
        for use_type, items in to_remove.items():
            for i in items:
                merged[use_type].pop(i)

        return merged

    def _step_def_use_chain(self, diff_state: DifferentialTraceState, follow_regs: bool, follow_mem: bool, prefix: str) -> list[DifferentialTraceState]:
        """
        Go "up" one step in the def use chain for multiple traces at the same time. This returns a
        DifferentialTraceState for each register/memory location used by the current state.
        """
        cur_insts = [self._check_if_sink(s.tracer, s.line, prefix, s.val_name) for s in diff_state.states]
        if any(x is None for x in cur_insts):
            # TODO: what happens if only one finished? for now, we just stop exploring that path.

            return []

        for s, cur_inst in zip(diff_state.states, cur_insts):
            self._print(f"{prefix} using {s.val_name} defined by {self._get_short_descr(cur_inst, s.line)}")
            break # only print first, remove if you want full differential printing

        uses = [self._get_uses(i, prefix=prefix, regs=follow_regs, mem=follow_mem) for i in cur_insts]
        merged = _merge_uses(uses)

        if (len(uses) > 1):
            merged = self._filter_differential(merged, prefix)

        defs = self._get_defs(merged, diff_state)
        return defs

    def follow_def_use_chain_recursive(self, diff_states: list[DifferentialTraceState], follow_regs: bool, follow_mem: bool, prefix: str) -> None:
        """
        Recursively explore the def-use chain starting from a set of states.
        Only for the first step, we might want to follow only memory uses (for D-type violations)
        or only register uses (for I-type violations).
        """
        idx = 0
        for diff_state in diff_states:
            cur_lines = [s.line for s in diff_state.states]
            # Cache results to avoid recomputing stuff.
            if cur_lines in self._visited:
                self._print(prefix + "    └─ Skipping (already visited)")
                continue
            if all(x != None for x in cur_lines):
                self._visited.append(cur_lines)

            # Check if it's the last state.
            if idx == len(diff_states) - 1:
                cur_prefix = prefix + "    └─"
            else:
                cur_prefix = prefix + "    ├─"

            # Perform one reverse step in the def-use chain.
            next_list = self._step_def_use_chain(diff_state, follow_regs, follow_mem, cur_prefix)
            if idx == len(diff_states) - 1:
                next_prefix = prefix + "     "
            else:
                next_prefix = prefix + "    │"

            # Follow all the uses recursively.
            self.follow_def_use_chain_recursive(next_list, follow_regs=True, follow_mem=True, prefix=next_prefix)
            idx += 1

    def analyze(self, raw_trace1: list[Any], line1: int, raw_trace2: list[Any], line2: int, violation: str) -> None:
        # Initialize trace(s)
        trace1 = TraceBundle.from_trace(raw_trace1, line1)
        trace2 = None
        if raw_trace2 is not None:
            trace2 = TraceBundle.from_trace(raw_trace2, line2)

        if violation == "D":
            # data violation: get all MEM_USES
            init_state = DifferentialTraceState([trace1])
            if trace2 is not None:
                init_state.states.append(trace2)
            self.follow_def_use_chain_recursive(diff_states=[init_state],
                                        prefix="", follow_mem=True, follow_regs=False)

        elif violation == "I":
            # PC violation: 1. go to previous instruction
            # NOTE: if a trace has two different PCs it means that the control-flow
            # instruction immediately preceding them had a different outcome.
            trace1.tracer.prev_entry()
            trace1.update_line(trace1.tracer.cur_idx)
            init_state = DifferentialTraceState([trace1])
            if trace2 is not None:
                trace2.tracer.prev_entry()
                trace2.update_line(trace2.tracer.cur_idx)
                init_state.states.append(trace2)
            # 2. follow all reg uses of the previous instruction
            self.follow_def_use_chain_recursive(diff_states=[init_state],
                                                prefix="", follow_mem=False, follow_regs=True)

        else:
            self._out_file.close()
            assert False, "Unknown violation type"

        self._out_file.close()
