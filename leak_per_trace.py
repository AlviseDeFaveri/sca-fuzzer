import sys
import os
import IPython
import json

KNOWN_VULNS = [
            "lib/aes-c.c:73",
            "lib/aes-c.c:74",
            "lib/aes-c.c:75",
            "lib/aes-c.c:76",
            "lib/aes-c.c:97",
            "lib/aes-c.c:98",
            "lib/aes-c.c:99",
            "/home/alvise/sw-testing/SymCrypt/build/lib/amd64/aesasm-gas.asm:286",
            "/home/alvise/sw-testing/SymCrypt/build/lib/amd64/aesasm-gas.asm:282",
]

if len(sys.argv) != 2:
    print(f"Usage {sys.argv[0]} <report>")
    sys.exit(-1)

with open(sys.argv[1]) as f:
    data = json.load(f)

reverse_map = {}
for v1 in data.values():
    for v2 in v1.values():
        for k, v3 in v2.items():
            if k in KNOWN_VULNS:
                continue
            for v4 in v3.values():
                for l in v4:
                    trace_file = ":".join(l.split(":")[:-2])
                    trace_folder = "/".join(trace_file.split("/")[:-1])
                    if trace_folder not in reverse_map.keys():
                        reverse_map[trace_folder] = {}
                    if trace_file not in reverse_map[trace_folder].keys():
                        reverse_map[trace_folder][trace_file] = []
                    reverse_map[trace_folder][trace_file].append(k)
                    reverse_map[trace_folder][trace_file] = set(reverse_map[trace_folder][trace_file])
                    reverse_map[trace_folder][trace_file] = list(reverse_map[trace_folder][trace_file])

with open(sys.argv[1].replace('.json', '.reverse.json'), 'w', encoding='utf-8') as f:
  json.dump(reverse_map, f, sort_keys=True, indent=4)
