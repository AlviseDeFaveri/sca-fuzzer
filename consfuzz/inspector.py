#!/usr/bin/python3

import subprocess as sp
from typing import Any
import argparse
import os

from rvzr.model_dynamorio.trace_decoder import TraceDecoder, TraceEntryType, DebugTraceEntryType
from inspector.use_def_tracker import UseDefTracker
from inspector import get_plugin_path
from utils.config import Config
from utils.symbol_server import SymbolServer, CombinedSymbolServer

_TRACING_FLAGS = "--log-level 5 --debug-trace-output {dbg_trace_file} --print-debug-trace "

class LeakageInspector:
    """
    Extract information for leakage analysis from the reporter's output.
    """
    _decoder: TraceDecoder

    leak_trace: list[Any]
    debug_trace: list[Any]

    def __init__(self):
        self._decoder = TraceDecoder()
        self.leak_trace = None
        self.debug_trace = None

    #---------------------------------------------------------------------------
    # Internal Helpers
    #---------------------------------------------------------------------------
    def _count_occurrences(self, trace: list[Any], is_dbg_trace: bool, pc: int, until: int, only_arch: bool = False) -> int:
        """
        Count occurrences of `pc` in `trace` before line `until`.
        """
        count = 0
        for entry in trace[:until]:
            # Check pc for debug traces
            if is_dbg_trace:
                type_ = DebugTraceEntryType(entry.type)
                if only_arch and self._is_spec(entry):
                    continue
                if type_ == DebugTraceEntryType.ENTRY_REG_DUMP and entry.regs.pc == pc:
                    count +=1
            # Check pc for normal traces
            else:
                type_ = TraceEntryType(entry.type)
                if type_ == TraceEntryType.ENTRY_PC and entry.addr == pc:
                    count +=1
        return count

    def _is_arch(self, entry: Any) -> bool:
        """
        Is the entry architectural (debug trace entries only)
        """
        return entry.nesting_level == 0

    def _is_spec(self, entry: Any) -> bool:
        """
        Is the entry speculative (debug trace entries only)
        """
        return entry.nesting_level != 0

    def _get_original_cmd(self, trace_file: str) -> str:
        """
        Get the original command that was ran to produce a given trace.
        NOTE: This requires that the original dynamoRIO command is logged in a separate `.log`
        file that has the same name of the trace file (minus the extension).
        """
        log_file = trace_file.replace(".trace", ".log")
        print(f" • Reading original command from logfile {log_file}", flush=True)
        with open(log_file, "r") as log:
            for l in log:
                if l.startswith("$> "):
                    return l.replace("$> ", "").replace("\n","").strip()

        raise ValueError(f"Could not find command that produced {trace_file}")

    def _run_dbg_tracer(self, trace_file: str, regenerate_trace: bool) -> str:
        """
        Produce a debug trace for a given test case.
        Returns the file name of the trace.
        """
        cmd = self._get_original_cmd(trace_file)

        # Add debug flags to command
        dbg_trace_f = trace_file.replace(".trace", ".dbgtrace")
        dbg_flags = _TRACING_FLAGS.format(dbg_trace_file=dbg_trace_f)
        cmd = cmd.replace("libdr_model.so", f"libdr_model.so {dbg_flags} ")
        # Output debug trace in human-readable format
        cmd += " > {dbg_trace_file}.asm".format(dbg_trace_file=dbg_trace_f)
        # Run debug command
        if regenerate_trace:
            print(f"{cmd}\n", flush=True)
            sp.check_call(cmd, shell=True)

        return dbg_trace_f

    #---------------------------------------------------------------------------
    # Leak trace analysis
    #---------------------------------------------------------------------------
    def find_leak_pc(self, trace_file: str, trace_line: int) -> tuple[int,int]:
        """
        Given a trace file and a corresponding line, returns the corresponding PC and the
        number of occurrences of that PC before that line.
        """
        print(f" • Decoding trace {trace_file}...", flush=True)
        traces, _ = self._decoder.decode_trace_file(trace_file)
        assert len(traces) == 1
        trace = traces[0]
        self.leak_trace = trace
        # Find last pc right before trace_line
        print(" • Finding leak PC...", flush=True)
        cur_line = trace_line
        while cur_line > 0:
            # For different PCs, we want to get the PC of the previous instruction
            # For different mem accesses, we want to get the PC of the load/store instruction
            cur_line -= 1
            entry = trace[cur_line]
            if TraceEntryType(entry.type) == TraceEntryType.ENTRY_PC:
                # Found previous instruction
                leak_pc = entry.addr
                n_occurrences = self._count_occurrences(trace, is_dbg_trace=False, pc=leak_pc, until=cur_line)
                n_occurrences += 1 # count also the last occurrence that we just found
                print(f" • Found address {hex(leak_pc)} (occurrence #{n_occurrences})", flush=True)
                return (leak_pc, n_occurrences)

        raise ValueError(f"No instruction found for trace line {trace_line}")

    #---------------------------------------------------------------------------
    # Debug trace analysis
    #---------------------------------------------------------------------------
    def find_dbg_line(self, trace_file: str, leak_pc: int, leak_pc_count: int, regenerate_trace: bool) -> tuple[str, int]:
        """
        Find the line that contains the `leak_pc_count`-th occurrence of `leak_pc` in the debug trace.
        """
        print(" • Collecting debug trace...", flush=True)
        dbg_trace_f = self._run_dbg_tracer(trace_file, regenerate_trace)
        # Parse the debug trace
        print(" • Decoding debug trace...", flush=True)
        _, dbg_traces = self._decoder.decode_trace_file(dbg_trace_f)
        assert len(dbg_traces) == 1
        dbg_trace = dbg_traces[0]
        self.debug_trace = dbg_trace

        last_lineno = 0
        n_found = 0

        print(" • Analyzing debug trace...", flush=True)
        for entry in dbg_trace:
            if DebugTraceEntryType(entry.type) == DebugTraceEntryType.ENTRY_REG_DUMP:
                if entry.regs.pc == leak_pc:
                    n_found += 1

                if n_found == leak_pc_count:
                    print(f"Done! Found leak at line {last_lineno-1}")
                    return dbg_trace_f, last_lineno-1

            last_lineno += 1

        raise IndexError(f"Could not find occurence {leak_pc_count} of pc {hex(leak_pc)} in {dbg_trace_f}")

    #---------------------------------------------------------------------------
    # GDB
    #---------------------------------------------------------------------------
    def generate_gdb_script(self, trace_file: str, trace_line: int) -> str:
        """
        Generate a GDB script that can follow the trace speculatively until the leakage point.
        """
        gdb_string = f"source {get_plugin_path()}/plugin.py"
        gdb_string += "\nspec source " + trace_file
        gdb_string += "\nspec goto " + str(trace_line)
        gdb_string += "\nspec bt"
        return gdb_string


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Inspect a leakage.")
    parser.add_argument("file_and_line", type=str, help="<trace_file:line1:line2> where to start from")
    parser.add_argument("-b", "--binary", type=str,
                        help="Path of the binary to read the debug symbols from.",
                        default=None)
    parser.add_argument("-c", "--config", type=str, help="Path of the yaml config", default=Config.get_default_config())
    parser.add_argument("-v", "--violation", type=str, help="Which violation has been found at that PC", choices=["I", "D"])
    parser.add_argument("--skip-tracing", action="store_true", help="Avoid regenerating traces")
    args = parser.parse_args()

    # Get path and line of the leak we want to target
    splitted = args.file_and_line.split(':')
    trace1 = ':'.join(splitted[:-2])
    line1 = int(splitted[-2])
    # Get path and line of the baseline
    input_name = os.path.basename(trace1)
    trace2 = trace1.replace(input_name, 'private_000.trace')
    line2 = int(splitted[-1])

    # Run the debug tracer and find the corresponding line for both target and baseline
    inspector = LeakageInspector()
    traces = [(trace1, line1), (trace2, line2)]
    dbg_traces = []
    idx = 0
    for trace, line in traces:
        # Go from trace:line to dbg_trace:dbg_line
        pc, n_occurrences = inspector.find_leak_pc(trace, line)
        regenerate_trace = not args.skip_tracing
        dbg_trace, dbg_line = inspector.find_dbg_line(trace, pc, n_occurrences, regenerate_trace)

        # Create the gdb script to reach that line
        script = inspector.generate_gdb_script(dbg_trace, dbg_line)
        script_name = f"spec_{idx}.gdb"
        with open(script_name, "w") as f:
            f.write(script)
        # Print the gdb command (user can copy-paste in separate terminal)
        program_cmd = inspector._get_original_cmd(trace).split(" -- ")[1]
        print(f"\n====== GDB Command:\ngdb -x {script_name} --args {program_cmd}\n======")

        # Append the already parsed trace, used later for use-def analysis
        raw_dbg_trace = inspector.debug_trace
        dbg_traces.append((raw_dbg_trace, dbg_line))

        idx += 1

    # Create output file
    use_def_file = trace1.replace('.trace', '.usedef')
    print(f"\n====== Printing use-def information at {use_def_file}")
    # Setup symbol server
    symbols = SymbolServer("") if args.binary is None else CombinedSymbolServer(args.binary) # GdbSymbolServer(binary)
    # Setup configuration
    Config.init(args.config)
    # Print use-def chain to a file
    tracker = UseDefTracker(use_def_file, symbols)
    graph = tracker.analyze(dbg_traces[0][0], dbg_traces[0][1], dbg_traces[1][0], dbg_traces[1][1], args.violation)
    # graph.print_recursive()
    dot_file = "out.dot"
    print(f"\n====== Printing graph at {dot_file}")
    graph.draw(dot_file)
