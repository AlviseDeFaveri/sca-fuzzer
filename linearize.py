import sys
import os

if len(sys.argv) != 3:
    print(f"Usage {sys.argv[0]} <TRACE_FILE> <LINE>")
    sys.exit(1)

trace_file = sys.argv[1]
line_no = int(sys.argv[2])

lines = []
trace =[[], []]
cur_level = 0

with open(trace_file, "r") as f:
    idx = 0
    while l := f.readline():
        if l.startswith("[ARCH"):
            trace[0].append(l.replace("\n",""))
            if cur_level != 0:
                trace[1] = []
                cur_level = 0
        elif l.startswith("[SPEC_1"):
            cur_level = 1
            trace[1].append(l.replace("\n",""))
        elif l.startswith("SPEC_"):
            print("Error: nested spec windows not supported yet")
            sys.exit(-1)
        if idx == line_no:
            break
        idx +=1

out_trace = trace[0] + trace[1]
for o in out_trace:
    print(o)
