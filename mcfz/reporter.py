"""
File: Module responsible for Stage 3 of the fuzzing process: analysis of the collected traces
      and reporting of the results.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from typing import TYPE_CHECKING, List, Tuple, Dict, Iterator, NewType, Any, Set

import os
import json
from copy import deepcopy

from .leak_detector import LeakageMap, LeakType, ClauseType, PC, LinesInTracePair, PolicyType
from .util.dwarf import ModulesInfo

if TYPE_CHECKING:
    from .config import Config, ReportVerbosity

# ==================================================================================================
# Local type definitions
# ==================================================================================================
CodeLine = NewType('CodeLine', str)
""" Location of a line in the source code, used to group leaks by code lines.
    It is a string in the format "filename:line_number", where
    * filename is the name of the source file,
    * line_number is the line number in the source file.
"""

LeakageLineMap = Dict[
    ClauseType,
    Dict[
        LeakType,
        Dict[
            str,      # effective policy (e.g. "key", "plain", "key+plain")
            Dict[
                CodeLine,
                Dict[
                    PC,
                    List[LinesInTracePair],
                ],
            ],
        ],
    ]
]
""" Map of unique leaky lines of code, indexed by clause, leak type, policy, and code line.
    When a code line is observed under multiple policies it is stored under a combined key
    formed by joining the sorted policy names with "+" (e.g. "key+plain").
    The innermost value is a map of PCs to the trace locations where the leak was found.
"""


# ==================================================================================================
# Reporting of the analysis results
# ==================================================================================================
def _convert_int_keys_to_hex(o: Any) -> Any:
    """Recursively convert all integer dictionary keys to hex strings."""
    if isinstance(o, dict):
        return {
            (hex(k) if isinstance(k, int) else k): _convert_int_keys_to_hex(v) for k, v in o.items()
        }
    if isinstance(o, list):
        return [_convert_int_keys_to_hex(item) for item in o]
    if isinstance(o, int):
        return hex(o)
    return o


class _ReportPrinter:
    """
    Class responsible for printing the analysis results to a report file.
    """

    def __init__(self, config: Config) -> None:
        self._config = config
        self._modules_info = ModulesInfo(os.path.join(config.stage3_wd, "mappings.txt"))

    def final_report(self, leakage_map: LeakageMap, report_dir: str) -> None:
        """ Print the global map of leaks to the trace log """
        all_levels: List[ReportVerbosity] = [1, 2, 3]
        leakage_line_map = self._group_by_code_line(leakage_map)
        leakage_line_map = self._filter_allowlist(leakage_line_map)
        for verbosity in all_levels:
            report_file = os.path.join(report_dir, f"report_verbosity_{verbosity}.json")
            self._write_report(report_file, leakage_line_map, verbosity)

    def _write_report(self, report_file: str, leakage_line_map: LeakageLineMap,
                      verbosity: 'ReportVerbosity') -> None:
        """
        Write the report to the given file in a json format.

        Verbosity controls the depth of the output:
          1 → clause / leak_type / policy / code_line  (code_lines as sorted list)
          2 → + PC                                     (PCs as sorted list per code_line)
          3 → + LinesInTracePair                       (full trace locations per PC)
        """
        if verbosity == 1:
            out: Any = {
                clause: {
                    lt: {
                        policy: sorted(per_policy.keys())
                        for policy, per_policy in per_type.items()
                    }
                    for lt, per_type in per_clause.items()
                }
                for clause, per_clause in leakage_line_map.items()
            }
        elif verbosity == 2:
            out = {
                clause: {
                    lt: {
                        policy: {
                            code_line: sorted(per_line.keys())
                            for code_line, per_line in per_policy.items()
                        }
                        for policy, per_policy in per_type.items()
                    }
                    for lt, per_type in per_clause.items()
                }
                for clause, per_clause in leakage_line_map.items()
            }
        else:  # verbosity == 3
            out = leakage_line_map

        report_dict = _convert_int_keys_to_hex(out)
        with open(report_file, "w") as f:
            json.dump(report_dict, f, indent=4, sort_keys=True)

    def _group_by_code_line(self, leakage_map: LeakageMap) -> LeakageLineMap:
        """
        Transform a LeakageMap into a LeakageLineMap by grouping all instructions that map to
        the same source code line, collapsing cross-policy duplicates, and filtering COND leaks
        that are already reported under SEQ.
        """
        leakage_line_map: LeakageLineMap = {}
        for clause, leak_type, policy, code_line, pc, locs in \
                self._iter_leaks_with_code_lines(leakage_map):
            (leakage_line_map
             .setdefault(clause, {})
             .setdefault(leak_type, {})
             .setdefault(policy, {})
             .setdefault(code_line, {})
             .setdefault(pc, [])
             .extend(locs))
        # Collapse code_lines found under multiple policies into a combined policy key
        for clause, clause_map in leakage_line_map.items():
            for leak_type, value in clause_map.items():
                clause_map[leak_type] = self._collapse_policies(value)
        # Remove COND violations that were also found architecturally (SEQ)
        for leak_type in leakage_line_map.get('seq', {}).keys():
            if leak_type in leakage_line_map.get('cond', {}).keys():
                leakage_line_map['cond'][leak_type] = self._filter_cond(
                    leakage_line_map, leak_type)
        # Sort all trace location lists
        for per_clause in leakage_line_map.values():
            for per_type in per_clause.values():
                for per_policy in per_type.values():
                    for per_line in per_policy.values():
                        for loc_list in per_line.values():
                            loc_list.sort()
        return leakage_line_map

    def _iter_leaks_with_code_lines(self, leakage_map: LeakageMap) \
            -> Iterator[Tuple[ClauseType, LeakType, PolicyType, CodeLine, PC,
                              List[LinesInTracePair]]]:
        """Yield (clause, leak_type, policy, code_line, pc, locs) for every leak in the map."""
        for clause_type in leakage_map:
            for leak_type in leakage_map[clause_type]:
                for policy in leakage_map[clause_type][leak_type]:
                    per_policy_map = leakage_map[clause_type][leak_type][policy]
                    for pc in per_policy_map:
                        source_code_line = CodeLine(self._modules_info.resolve_address(pc))
                        yield clause_type, leak_type, policy, source_code_line, pc, \
                            per_policy_map[pc]

    def _filter_cond(self, leakage_line_map: LeakageLineMap, leak_type: LeakType) \
            -> Dict[str, Dict[CodeLine, Dict[PC, List[LinesInTracePair]]]]:
        """Remove COND violations that were also found architecturally (SEQ).

        A code line is suppressed from COND policy P only when it appears in SEQ under a
        policy P' that *overlaps* with P (i.e. they share at least one raw policy component).
        Examples (policies "key" and "plain"):
          - SEQ "key"       → suppresses COND "key" and "key+plain", but NOT "plain"
          - SEQ "plain"     → suppresses COND "plain" and "key+plain", but NOT "key"
          - SEQ "key+plain" → suppresses COND "key", "plain", and "key+plain"
        """
        seq_map = leakage_line_map.get('seq', {}).get(leak_type, {})
        cond_map = leakage_line_map.get('cond', {}).get(leak_type, {})

        filtered: Dict[str, Dict[CodeLine, Dict[PC, List[LinesInTracePair]]]] = {}
        for cond_policy, per_policy in cond_map.items():
            cond_raw = set(cond_policy.split("+"))
            seq_code_lines: Set[CodeLine] = set()
            for seq_policy, seq_per_policy in seq_map.items():
                seq_raw = set(seq_policy.split("+"))
                if cond_raw & seq_raw:
                    seq_code_lines.update(seq_per_policy.keys())
            filtered[cond_policy] = {cl: v for cl, v in per_policy.items()
                                     if cl not in seq_code_lines}
        return filtered

    @staticmethod
    def _collapse_policies(
            per_type_map: Dict[str, Dict[CodeLine, Dict[PC, List[LinesInTracePair]]]]) \
            -> Dict[str, Dict[CodeLine, Dict[PC, List[LinesInTracePair]]]]:
        """Merge code_lines found under multiple policies into a combined key
        (e.g. "key" + "plain" → "key+plain"); per-PC location lists are merged."""
        code_line_to_policies: Dict[CodeLine, List[str]] = {}
        for policy, per_policy in per_type_map.items():
            for code_line in per_policy:
                code_line_to_policies.setdefault(code_line, []).append(policy)

        result: Dict[str, Dict[CodeLine, Dict[PC, List[LinesInTracePair]]]] = {}
        for code_line, policies in code_line_to_policies.items():
            combined = "+".join(sorted(policies))
            merged: Dict[PC, List[LinesInTracePair]] = {}
            for p in policies:
                for pc, locs in per_type_map[p][code_line].items():
                    merged.setdefault(pc, []).extend(locs)
            result.setdefault(combined, {})[code_line] = merged
        return result

    def _is_allowlisted(self, code_line: str, allowlist: Set[str]) -> bool:
        return any(code_line == entry or code_line.endswith("/" + entry) for entry in allowlist)

    def _filter_allowlist(self, leakage_line_map: LeakageLineMap) -> LeakageLineMap:
        """
        Filter the leakage line map by the allowlist of source code lines.
        The allowlist is a list of source code lines that should be excluded from the report.
        Entries support partial path matching: ``filename.c:123`` in the allowlist will match
        ``/path/to/filename.c:123`` in the leakage map.
        """
        allowlist_file = self._config.allowlist
        if not allowlist_file:
            return leakage_line_map

        with open(allowlist_file, "r") as f:
            allowlist = {line.strip() for line in f if line.strip()}

        filtered = deepcopy(leakage_line_map)
        for clause in leakage_line_map:
            for leak_type in leakage_line_map[clause]:
                for policy in leakage_line_map[clause][leak_type]:
                    per_policy_map = leakage_line_map[clause][leak_type][policy]
                    filtered_per_policy = filtered[clause][leak_type][policy]
                    for code_line in per_policy_map:
                        if self._is_allowlisted(code_line, allowlist):
                            filtered_per_policy.pop(code_line)
        return filtered


# ==================================================================================================
# Public interface to the analysis and reporting module
# ==================================================================================================
class Reporter:
    """
    Class responsible for processing the collected contract traces, detecting leaks exposed in them,
    and building a final report with the results of the analysis.
    """

    def __init__(self, config: Config) -> None:
        self._config = config

        # check that mappings.txt was created (it's a common source of errors)
        if not os.path.isfile(os.path.join(self._config.stage3_wd, "mappings.txt")):
            raise FileNotFoundError(
                "Module mappings file 'mappings.txt' not found in stage 3 working directory "
                f"'{self._config.stage3_wd}'.")

    def generate_report(self, leakage_map: LeakageMap) -> None:
        """
        Generate a report of the leaks found in the fuzzing campaign.
        """
        printer = _ReportPrinter(self._config)
        printer.final_report(leakage_map, self._config.stage4_wd)
