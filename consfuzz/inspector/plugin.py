"""
File: GDB plugin that can be used to navigate traces in GDB.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""

import gdb

# FIXME!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
import sys
sys.path.append("/home/alvise/venv-revizor-2/lib/python3.12/site-packages")
sys.path.append(".")
sys.path.append("gdb_plugin")

from typing import Any, Optional
from rvzr.model_dynamorio.trace_decoder import TraceDecoder, DebugTraceEntryType

# ------------------------------------------------------------------------------
# Trace Helpers
# ------------------------------------------------------------------------------

_glob_trace = None
_cached_lines = {}
_glob_cur_line = None
_glob_cur_level = 0

class SpecWinInfo:
    """
    Store relevant information about a specific speculative window.
    """
    first_pc: Optional[int]
    first_line: Optional[int]
    target_pc: int
    target_line: int
    target_count: int
    nesting: int

    def __init__(self, first_pc: Optional[int], first_line: Optional[int], target_pc: int, target_line: int, target_count: int, nesting: int):
        self.first_pc = first_pc
        self.target_pc = target_pc
        self.target_count = target_count
        self.nesting = nesting
        self.first_line = first_line
        self.target_line = target_line

    def __str__(self):
        prefix  = "    " * self.nesting
        if self.first_pc is None:
            return f"{prefix} └─ last architectural: {hex(self.target_pc)} (#{self.target_count}) [line: {self.target_line}]"

        s  = f"{prefix} ├─ speculates to: {hex(self.first_pc)} [line: {self.first_line}]\n"
        s += f"{prefix} └─ until: {hex(self.target_pc)} (#{self.target_count}) [line: {self.target_line}]"
        return s


def _is_arch(entry: Any) -> bool:
    """
    Is the entry architectural (debug trace entries only)
    """
    return entry.nesting_level == 0

def _is_spec(entry: Any) -> bool:
    """
    Is the entry speculative (debug trace entries only)
    """
    return entry.nesting_level != 0

def _build_spec_info(line):
    """
    Return a list of relevant information for each (nested) speculation window that leads to the
    instruction at line `line` in the trace.
    """
    spec_windows: list[SpecWinInfo] = []

    print(f" • Analyzing debug trace from line {line}...", flush=True)
    cur_idx = line
    prev_nesting = None

    while cur_idx > 0:
        # Visit trace in reverse order
        entry = _glob_trace[cur_idx]

        if DebugTraceEntryType(entry.type) == DebugTraceEntryType.ENTRY_REG_DUMP:
            # Found new instruction
            cur_pc = entry.regs.pc
            cur_nesting = entry.nesting_level
            if len(spec_windows) > 0:
                prev_nesting = spec_windows[-1].nesting

            if prev_nesting is None or cur_nesting < prev_nesting:
                # Found start of new speculation window
                start_spec_pc = cur_pc if _is_spec(entry) else None
                start_spec_line = cur_idx if _is_spec(entry) else None
                spec_windows.append(SpecWinInfo(start_spec_pc, start_spec_line, cur_pc, cur_idx, 1, cur_nesting))
            elif cur_nesting == prev_nesting:
                # Update the current speculation window
                if spec_windows[-1].first_pc is not None:
                    spec_windows[-1].first_pc = cur_pc
                    spec_windows[-1].first_line = cur_idx
                if cur_pc == spec_windows[-1].target_pc:
                    spec_windows[-1].target_count += 1

        cur_idx -= 1

    return spec_windows

def _get_line_info(line: int):
    """
    Return the relevant information for a given line (take from the cache if already computed).
    """
    if line in _cached_lines.keys():
        spec_windows = _cached_lines[line]
    else:
        spec_windows = _build_spec_info(line)
        _cached_lines[line] = spec_windows

    return spec_windows

# ------------------------------------------------------------------------------
# GDB Helpers
# ------------------------------------------------------------------------------

_glob_n_bp = 0

class Printing:
    """
    Customize the amount of information printed when running commands
    """
    @staticmethod
    def setup():
        gdb.execute("set print frame-arguments presence")

    @staticmethod
    def restore():
        gdb.execute("set print frame-arguments all")

class Breakpoints:
    """
    Breakpoints management
    """
    @staticmethod
    def add(bp: str | int) -> int:
        global _glob_n_bp
        if isinstance(bp, int):
            gdb.execute(f"b *{hex(bp)}", to_string=True)
        else:
            gdb.execute(f"b {bp}", to_string=True)

        _glob_n_bp += 1
        return _glob_n_bp

    @staticmethod
    def delete(n: int):
        gdb.execute(f"del {n}")

    @staticmethod
    def ignore(bp: int, count: int):
        gdb.execute(f"ignore {bp} {count}")


class GdbExec:
    @staticmethod
    def run():
        gdb.execute("run", to_string=True)

    @staticmethod
    def cont():
        gdb.execute("continue", to_string=True)

    @staticmethod
    def backtrace():
        gdb.execute("bt")

    @staticmethod
    def jump(target_pc: int):
        gdb.execute(f"jump *{hex(target_pc)}", to_string=True)

# ------------------------------------------------------------------------------
# GDB Commands
# ------------------------------------------------------------------------------
class SpecPrefixCommand (gdb.Command):
  "Spec command."

  def __init__ (self):
    super (SpecPrefixCommand, self).__init__ ("spec",
                         gdb.COMMAND_SUPPORT,
                         gdb.COMPLETE_NONE, prefix=True)

SpecPrefixCommand()


class SpecSourceCommand (gdb.Command):
    """
    Load a debug trace generate by consfuzz.
    """
    def __init__ (self):
        super (SpecSourceCommand, self).__init__ ("spec source",
                                                       gdb.COMMAND_SUPPORT,
                                                       gdb.COMPLETE_FILENAME)
        self._decoder = TraceDecoder()

    def invoke (self, arg, from_tty):
        # Parse the debug trace
        print(f" • Decoding debug trace... {arg}", flush=True)

        _, dbg_traces = self._decoder.decode_trace_file(arg)
        if len(dbg_traces) != 1:
            print(" • Error! Not a debug trace.")
            return
        global _glob_trace
        _glob_trace = dbg_traces[0]

        # Run the program
        bp = Breakpoints.add("wrapper")
        GdbExec.run()
        Breakpoints.delete(bp)

        print(" • Done!")

SpecSourceCommand ()


def spec_goto():
    # Get spec info for the given line
    global _glob_cur_line
    global _glob_cur_level
    spec_windows = _get_line_info(_glob_cur_line)

    Printing.setup()
    # Simulate all windows
    for win in reversed(spec_windows[_glob_cur_level:]):
        # Check if we need to open a speculation window
        if win.first_pc is not None:
            # Break on the first speculative instruction
            bp = Breakpoints.add(win.first_pc)
            # Jump to the first speculative instruction (stops at previous breakpoint)
            GdbExec.jump(win.first_pc)
            # Disable entrypoint (in case it's visited again in the rest of the trace)
            Breakpoints.delete(bp)

        # Break on last instruction of the window
        bp = Breakpoints.add(win.target_pc)
        # Continue until the right number of occurrences have been found
        Breakpoints.ignore(bp, win.target_count - 1)
        GdbExec.cont()
        # Disable breakpoint (in case we encounter this instruction again later in the trace)
        Breakpoints.delete(bp)
        # Print Backtrace
        # print(f"------------------- Reached {hex(win.target_pc)} ----------------------")
        # GdbExec.backtrace()

    Printing.restore()
    gdb.execute("dash")


class SpecGotoCommand (gdb.Command):
    """
    Execute the program until we reach the instruction corresponding to the given line.
    """
    def __init__ (self):
        super (SpecGotoCommand, self).__init__ ("spec goto",
                                                       gdb.COMMAND_SUPPORT,
                                                       gdb.COMPLETE_FILENAME)
        global _glob_n_bp
        _glob_n_bp = 0

    def invoke (self, arg, from_tty):
        # Check validity of state and inputs
        if _glob_trace is None:
            print ("Error: no trace is sourced")
            return
        try:
            arg = int(arg)
        except:
            print ("Error: command expects a line number")
            return
        if arg > len(_glob_trace):
            print ("Error: invalid line for current trace")
            return

        global _glob_cur_line
        _glob_cur_line = arg

        spec_goto()

SpecGotoCommand ()


class SpecBtCommand (gdb.Command):
    """
    Get information about speculation backtrace for the currently selected line.
    """
    def __init__ (self):
        super (SpecBtCommand, self).__init__ ("spec bt",
                                                       gdb.COMMAND_SUPPORT,
                                                       gdb.COMPLETE_FILENAME)

    def invoke (self, arg, from_tty):
        # Check validity of state and inputs
        global _glob_cur_line
        global _glob_cur_level
        if _glob_cur_line is None:
            print ("Error: no line selected - use 'spec goto' to select one")
            return

        # Get spec info for the given line
        spec_windows = _get_line_info(_glob_cur_line)

        # Print spec info
        for win in reversed(spec_windows[_glob_cur_level:]):
            print(win)

SpecBtCommand ()


class SpecUpCommand (gdb.Command):
    """
    Goto "up" int the speculative backtrace, i.e. to the last instruction before speculation.
    """
    def __init__ (self):
        super (SpecUpCommand, self).__init__ ("spec up",
                                                       gdb.COMMAND_SUPPORT,
                                                       gdb.COMPLETE_FILENAME)

    def invoke (self, arg, from_tty):
        global _glob_cur_line
        global _glob_cur_level

        # Check validity of state and inputs
        if _glob_cur_line is None:
            print ("Error: no line selected - use 'spec goto' to select one")
            return
        if _glob_cur_level >= len(_cached_lines[_glob_cur_line]) - 1:
            print ("Already at top level")
            return

        _glob_cur_level += 1
        spec_goto()

SpecUpCommand()


class SpecDownCommand (gdb.Command):
    """
    Goto "down" int the speculative backtrace, i.e. to the last instruction of the next window.
    """
    def __init__ (self):
        super (SpecDownCommand, self).__init__ ("spec down",
                                                       gdb.COMMAND_SUPPORT,
                                                       gdb.COMPLETE_FILENAME)

    def invoke (self, arg, from_tty):
        global _glob_cur_line
        global _glob_cur_level

        # Check validity of state and inputs
        if _glob_cur_line is None:
            print ("Error: no line selected - use 'spec goto' to select one")
            return
        if _glob_cur_level == 0:
            print ("Already at bottom level")
            return

        _glob_cur_level -= 1
        spec_goto()

SpecDownCommand()


class SpecPrevCommand (gdb.Command):
    """
    Goto the previous instruction in the trace that belongs to the same speculation window
    """
    def __init__ (self):
        super (SpecPrevCommand, self).__init__ ("spec prev",
                                                       gdb.COMMAND_SUPPORT,
                                                       gdb.COMPLETE_FILENAME)

    def invoke (self, arg, from_tty):
        global _glob_cur_line
        global _glob_cur_level
        global _glob_trace

        while True:
            if _glob_cur_line == 0:
                print("Already at first instruction!")
                return
            # Get previous instruction
            _glob_cur_line -= 1
            entry = _glob_trace[_glob_cur_line]
            if DebugTraceEntryType(entry.type) == DebugTraceEntryType.ENTRY_REG_DUMP:
                # Found new instruction
                spec_goto()
                break

SpecPrevCommand()


class SpecNextCommand (gdb.Command):
    """
    Goto the next instruction in the trace that belongs to the same speculation window
    """
    def __init__ (self):
        super (SpecNextCommand, self).__init__ ("spec next",
                                                       gdb.COMMAND_SUPPORT,
                                                       gdb.COMPLETE_FILENAME)

    def invoke (self, arg, from_tty):
        global _glob_cur_line
        global _glob_cur_level
        global _glob_trace

        while True:
            if _glob_cur_line == len(_glob_trace) - 1:
                print("Already at last instruction!")
                return
            # Get previous instruction
            _glob_cur_line += 1
            entry = _glob_trace[_glob_cur_line]
            if DebugTraceEntryType(entry.type) == DebugTraceEntryType.ENTRY_REG_DUMP:
                # Found new instruction
                spec_goto()
                break

SpecNextCommand()
