# Parse a debug trace and build a tree representation of the speculative windows

from graphviz import Digraph
import sys
from enum import Enum
import subprocess as sp

class TraceState(Enum):
    SEQ = 1
    ROLLBACK_FOUND = 2
    CHECKPOINT_FOUND = 3
    ROLLBACK_INST_FOUND = 4
    ROLLBACK_LOC_FOUND = 5
    ROLLED_BACK = 6

if len(sys.argv) != 2:
    print(f"Usage {sys.argv[0]} <PARSED_DBG_TRACE>")

# Trace file
trace_path = sys.argv[1]
trace_f = open(trace_path)

# Graphviz Graph
dot = Digraph(comment=f'SpecViz tree for {trace_path}')
dot.node('Root', 'Start')

# Internal state
trace_state = TraceState.SEQ
cur_pc = 0
cur_loc = ''
n_inst = 0

node_id = 0
cur_stack = ['Root']
cur_checkpoints = ['Root']

cur_line = 0

def addr2line(binary_path, address):
    # Call addr2line with the binary and address
    result = sp.run(
        ["addr2line", "-e", binary_path, address],
        capture_output=True,
        text=True,
        check=True
    )
    return result.stdout.strip()


# Parse trace
while True:
    line = trace_f.readline()
    if line == "":
        break

    cur_line += 1

    if line.startswith('[ARCH]') or line.startswith('[SPEC]'):
        cur_pc = line.split('(')[0].split(':')[1].strip()
        n_inst += 1

    elif line.startswith('[LOC]'):
        # cur_loc = line.split(' ')[1].split('/')[-1].replace('\n','')
        cur_loc = line.split(' ')[1].replace('\n','')
        if 'drivers/bearssl' in cur_loc:
            cur_loc = '/home/alvise/rvzr-sw-eval/drivers/bearssl/bearssl+' + cur_loc.split('+')[1]

        if trace_state == TraceState.ROLLBACK_FOUND or trace_state == TraceState.CHECKPOINT_FOUND:
            # Add node
            node_name = f"n{node_id}"
            node_id += 1
            node_desc = cur_loc if len(cur_loc) > 0 else str(cur_pc)
            dot.node(node_name, node_desc)

            # Connect to top of stack
            parent = cur_stack[-1]
            label = 'SPEC' if trace_state == TraceState.CHECKPOINT_FOUND else f"{n_inst} insts"
            dot.edge(parent, node_name, label=label)
            n_inst = 0

            # New top of stack
            cur_stack.append(node_name)
            if trace_state == TraceState.ROLLBACK_FOUND:
                trace_state = TraceState.ROLLED_BACK
            else:
                trace_state = TraceState.SEQ

    elif line.startswith('[CHECK]'):
        # if trace_state != TraceState.SEQ:
        #     print("ERROR! Found a checkpoint during rollback")
        #     print(f"Last instruction [{cur_line}] pc:{cur_pc} ({cur_loc})")
        #     sys._exit(-1)

        # Add node
        node_name = f"n{node_id}"
        node_id += 1
        node_desc = str(cur_pc)
        if len(cur_loc) > 0:
            cur_loc = addr2line(cur_loc.split('+')[0], cur_loc.split('+')[1])
        dot.node(node_name, cur_loc if len(cur_loc) > 0 else str(cur_pc), shape='box')

        # Connect to top of stack
        parent = cur_stack[-1]
        dot.edge(parent, node_name, label=f"{n_inst} insts")
        n_inst = 0
        trace_state = TraceState.CHECKPOINT_FOUND

        # New top of stack
        cur_stack.append(node_name)
        cur_checkpoints.append(node_name)

    elif line.startswith('[ROLLBACK]') and 'rollback_pc' in line:
        last_checkpoint = cur_checkpoints.pop()
        cur_stack = [last_checkpoint]
        n_inst = 0
        trace_state = TraceState.ROLLBACK_FOUND


dot.render('specview.gv')
