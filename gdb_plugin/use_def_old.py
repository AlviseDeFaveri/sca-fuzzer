import sys
import os
import argparse
from typing import List, Optional, Tuple
from enum import Enum

from utils import Color, getc
from debug_symbols import SymbolServer, CombinedSymbolServer
from regs import REGS
from rvzr_trace import TraceState, ParsedInst
from config import Config

_glob_visited = []

def follow_def_use_chain(tracer: TraceState, idx: Optional[int], prefix: str, t: str) -> list[int]:
    if idx is None:
        print(f"{prefix}{getc(Color.RED, '---END--- Hit top!')} First use of {t}")
        return []

    tracer.seek(idx)
    cur_inst = tracer.parse_current()

    if any(cur_inst.get_loc().endswith(x) for x in Config.get().declassified):
        print(f"{prefix}{getc(Color.YELLOW, '---END--- Found declassified!')} {t} defined by {cur_inst.get_short_descr(idx)}")
        return []

    if any(cur_inst.get_loc().endswith(x) for x in Config.get().key):
        print(f"{prefix}{getc(Color.RED, '---END--- Found key!')} {t} defined by {cur_inst.get_short_descr(idx)}")
        return []

    print(f"{prefix} using {t} defined by {cur_inst.get_short_descr(idx)}")
    defs = []

    for address in cur_inst.get_mem_reads():
        name = Config.is_known_sym(address)
        if name is not None:
            print(''.join(prefix[:-2]) + '    ' + ''.join(prefix[-2:]) + getc(Color.YELLOW, f'---END--- Hit known input: {name}'))
            continue

        next_idx, e = tracer.find_last_def(address, until=idx, mem=True)
        defs.append((next_idx, getc(Color.BLUE, hex(address))))

    for reg in cur_inst.get_reg_uses():
        if REGS[reg] in Config.get().dont_follow:
            continue
        next_idx, e = tracer.find_last_def(reg, until=idx, mem=False)
        defs.append((next_idx, getc(Color.BLUE, REGS[reg])))

    return defs


def follow_def_use_chain_recursive(vals: list[int], prefix: str ="") -> None:
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
    parser = argparse.ArgumentParser(description="Print the reverse def-use chain of a value from a revizor debug trace.")
    parser.add_argument("trace_file", type=str, help="Path of the debug trace file (in binary format) to parse")
    parser.add_argument("line", type=int, help="Line of the initial value")
    parser.add_argument("-b", "--binary", type=str,
                        help="Path of the binary to read the debug symbols from." + \
                            " If not specified, the tool will output module+offset." + \
                            " Note that all symbols specified in the configuration are compared against these debug symbols.",
                        default=None)
    parser.add_argument("-c", "--config", type=str, help="Path of the yaml config", default="config.yaml")
    args = parser.parse_args()

    Config.init(args.config)
    if args.binary is None:
        symbols = SymbolServer("")
    else:
        symbols = CombinedSymbolServer(args.binary)

    # Initialize trace state
    print(f"Decoding trace file {args.trace_file}...")
    tracer = TraceState(args.trace_file, symbols)
    tracer.seek(args.line)
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

    init = [(tracer.find_last_def(x, until=args.line, mem=False)[0], REGS[x]) for x in start_inst.get_mem_uses()]
    follow_def_use_chain_recursive(init)
