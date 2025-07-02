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

type Reg = int
type MemAddr = int
type TraceLineNum = int
type NodeId = int

type UseDefEdge = Tuple[NodeId, NodeId, Reg | MemAddr]

class UseDefNode:
    inst: ParsedInst
    line: TraceLineNum

    def __init__(self, line: TraceLineNum):
        self.line = line

        self.prevs = []
        self.succs = []

    def parse(self, trace: TraceState):
        trace.seek(self.line)
        self.inst = trace.parse_current()

class UseDefGraph:
    nodes: dict[TraceLineNum, UseDefNode]
    edges: list[UseDefEdge]

    def __init__(self):
        pass

    def get_or_create(self, line: TraceLineNum):
        if line not in self.nodes.keys():
            self.nodes[line] = UseDefNode(line)
        return self.nodes[line]

    def link(self, src: TraceLineNum, dst: TraceLineNum, val: Reg | MemAddr):
        self.edges.append(UseDefEdge(src, dst, val))


def get_defs(tracer: TraceState, node: UseDefNode) -> list[UseDefNode]:
    if node is None:
        return []

    node.parse(tracer)

    if any(node.inst.get_loc().endswith(x) for x in Config.get().declassified):
        return []

    if any(node.inst.get_loc().endswith(x) for x in Config.get().key):
        return []

    defs = []
    for address in node.inst.get_mem_reads():
        name = Config.is_known_sym(address)
        if name is not None:
            continue

        n = UseDefNode()
        n.line = tracer.find_last_def(address, until=node.line, mem=True)
        n.val = address
        n.succes.append(node)
        node.prevs.append(n)
        defs.append(n)

    for reg in node.inst.get_reg_uses():
        if REGS[reg] in Config.get().dont_follow:
            continue
        n = UseDefNode()
        n.line = tracer.find_last_def(reg, until=node.line, mem=False)
        n.val = reg
        n.succes.append(node)
        node.prevs.append(n)
        defs.append(n)

    return defs


def build_use_def_recursive(nodes: List[UseDefNode]) -> None:
    idx = 0
    for node in nodes:
        if node.line in _glob_visited:
            continue
        if node.line != None:
            _glob_visited.append(node.line)

        next_list = get_defs(tracer, node)

        build_use_def_recursive(next_list)
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
