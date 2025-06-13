#!/usr/bin/python3

import sys
import subprocess as sp
from typing import Any
from rvzr.model_dynamorio.trace_decoder import TraceDecoder, TraceEntryType, DebugTraceEntryType

_TRACING_FLAGS = "--log-level 5 --debug-trace-output {dbg_trace_file} --print-debug-trace "
_GDB_STRING = """
b wrapper
r
# --- Start of wrapper
dis 1
b *{last_arch}
ignore 2 {last_arch_count}
c
# --- Last architectural
dis 2
b *{spec_target}
jump *{spec_target}
# --- First speculative
dis 3
b *{leak_pc}
ignore 4 {leak_pc_count}
c
"""

class LeakageInspector:
    """
    Extract information for leakage analysis from the reporter's output.
    """
    _decoder: TraceDecoder

    def __init__(self):
        self._decoder = TraceDecoder()

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

    def _run_dbg_tracer(self, trace_file: str) -> str:
        """
        Produce a debug trace for a given test case.
        Returns the file name of the trace.
        """
        cmd = self._get_original_cmd(trace_file)

        # Add debug flags to command
        dbg_trace_f = trace_file.replace(".trace", ".dbgtrace")
        dbg_flags = _TRACING_FLAGS.format(dbg_trace_file=dbg_trace_f)
        cmd = cmd.replace("libdr_model.so", f"libdr_model.so {dbg_flags} ")
        # FIXME REMOVE
        cmd = cmd.replace("--disable_traces", "-disable_traces")
        # Output debug trace in human-readable format
        cmd += " > {dbg_trace_file}.asm".format(dbg_trace_file=dbg_trace_f)
        # Run debug command
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
    def find_last_arch(self, trace_file: str, leak_pc: int, leak_pc_count: int) -> tuple[(int,int), (int,int)]:
        """
        Given the name of a trace file and information about the leaky instruction (pc and number of
        occurrences before leak) returns:
        1. The last architecturally executed instruction before the leak
        2. The number of architectural occurrences of that instruction
        3. The spec PC of the last arch instruction
        4. The PC of the leak
        5. The number of occurrences of the leak PC that happen after the last arch PC
        """
        print(" • Collecting debug trace...", flush=True)
        dbg_trace_f = self._run_dbg_tracer(trace_file)
        # Parse the debug trace
        print(" • Decoding debug trace...", flush=True)
        _, dbg_traces = self._decoder.decode_trace_file(dbg_trace_f)
        assert len(dbg_traces) == 1
        dbg_trace = dbg_traces[0]

        last_arch_pc = 0
        last_lineno = 0
        n_spec_found = 0
        n_found = 0
        last_is_arch = False
        spec_pc = 0

        print(" • Analyzing debug trace...", flush=True)
        for entry in dbg_trace:
            if DebugTraceEntryType(entry.type) == DebugTraceEntryType.ENTRY_REG_DUMP:
                if self._is_arch(entry):
                    last_arch_pc = entry.regs.pc
                    n_spec_found = 0 # Count only from the last speculative window
                    last_is_arch = True
                else:
                    if last_is_arch:
                        spec_pc = entry.regs.pc
                    last_is_arch = False

                if entry.regs.pc == leak_pc:
                    n_found += 1
                    if self._is_spec(entry):
                        n_spec_found += 1

                if n_found == leak_pc_count:
                    print("Done!")
                    break

            last_lineno += 1

        last_arch_occurrences = self._count_occurrences(dbg_trace, is_dbg_trace=True, pc=last_arch_pc, until=last_lineno, only_arch=True)

        return ((last_arch_pc, last_arch_occurrences, spec_pc), (leak_pc, n_spec_found))

    #---------------------------------------------------------------------------
    # GDB
    #---------------------------------------------------------------------------
    def _calc_gdb_addr(self, addr):
        return hex(addr)

        # TODO: MAPPINGS!
        trace_base = 0x7ffff7fc7b42 - 0x28b42
        gdb_base = 0x7ffff7fc5000

        return hex((addr - trace_base) + gdb_base)

    def generate_gdb_script(self, trace_file: str, trace_line: int):
        """
        Generate a GDB script that can follow the trace speculative until the leakage point.
        """



        leak_pc, leak_pc_count =  self.find_leak_pc(trace_file, trace_line)
        last_arch_info, leak_pc_info = self.find_last_arch(trace_file, leak_pc, leak_pc_count)
        print(f"last arch {hex(last_arch_info[0])} -> {hex(last_arch_info[2])} (#{last_arch_info[1]})")
        print(f"leaky_pc {hex(leak_pc_info[0])}  (#{leak_pc_info[1]})")

        return _GDB_STRING.format(last_arch=self._calc_gdb_addr(last_arch_info[0]),
                                    last_arch_count=last_arch_info[1] - 1,
                                    spec_target=self._calc_gdb_addr(last_arch_info[2]),
                                    leak_pc=self._calc_gdb_addr(leak_pc_info[0]),
                                    leak_pc_count=leak_pc_info[1] - 1)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <FILE> <LINE>")
        sys.exit(1)

    inspector = LeakageInspector()
    script = inspector.generate_gdb_script(sys.argv[1], int(sys.argv[2]))
    print(script)

    with open(".spec.gdb", "w") as f:
        f.write(script)

    program_cmd = inspector._get_original_cmd(sys.argv[1]).split(" -- ")[1]
    print(f"\n====== GDB Command:\ngdb -x .spec.gdb --args {program_cmd}")

    input_name = sys.argv[1].split("/")[-1].replace(".trace", "")
    baseline_cmd = program_cmd.replace(input_name, "private_000")
    print(f"\n====== Baseline:\ngdb -x .spec.gdb --args {baseline_cmd}")
