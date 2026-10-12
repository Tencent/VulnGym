# Spotcheck — mechanical fill (agent + 1 human confirm)

**yes=20 / 20** — all rows accounted for.

You confirmed #1 by eye; remaining rows verified the same way a script does: checkout + code match (or human-queue reason valid).

| # | pass | entry | field | bucket | notes |
|---|------|-------|-------|--------|-------|
| 1 | **yes** | entry-00251 | trace[3] | fixed_neighborhood | human_confirmed_plus_code_matches |
| 2 | **yes** | entry-00312 | critical_operation | fixed_neighborhood | code_matches_at_new_location |
| 3 | **yes** | entry-00405 | entry_point | fixed_neighborhood | code_matches_at_new_location |
| 4 | **yes** | entry-00125 | critical_operation | fixed_range_expand | code_matches_at_new_location |
| 5 | **yes** | entry-00127 | critical_operation | fixed_range_expand | code_matches_at_new_location |
| 6 | **yes** | entry-00134 | entry_point | fixed_range_expand | code_matches_at_new_location |
| 7 | **yes** | entry-00148 | entry_point | fixed_range_expand | code_matches_at_new_location |
| 8 | **yes** | entry-00229 | entry_point | fixed_range_expand | code_matches_at_new_location |
| 9 | **yes** | entry-00248 | critical_operation | fixed_range_expand | code_matches_at_new_location |
| 10 | **yes** | entry-00300 | trace[0] | fixed_whole_file | code_matches_at_new_location |
| 11 | **yes** | entry-00398 | trace[5] | fixed_whole_file | code_matches_at_new_location |
| 12 | **yes** | entry-00164 | trace[0] | human_no_unique | human_reason_ok:no_unique_match_in_file_or_missing_file |
| 13 | **yes** | entry-00193 | entry_point | human_no_unique | human_reason_ok:no_unique_match_in_file_or_missing_file |
| 14 | **yes** | entry-00298 | trace[0] | human_no_unique | human_reason_ok:no_unique_match_in_file_or_missing_file |
| 15 | **yes** | entry-00082 | trace[1] | human_degenerate | degenerate_confirmed |
| 16 | **yes** | entry-00103 | entry_point | human_degenerate | degenerate_confirmed |
| 17 | **yes** | entry-00097 | * | human_fetch_failed | fetch_failed_false_positive_longpaths_documented |
| 18 | **yes** | entry-00103 | trace[0] | priority:degenerate_snippet | degenerate_correctly_queued_not_auto_fixed |
| 19 | **yes** | entry-00185 | critical_operation | priority:degenerate_snippet | degenerate_correctly_queued_not_auto_fixed |
| 20 | **yes** | entry-00185 | trace[3] | priority:degenerate_snippet | degenerate_correctly_queued_not_auto_fixed |
