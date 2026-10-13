#!/usr/bin/env python3
import json
import csv
import argparse
import sys
import os

def parse_line(line):
    """Normalize line representation to a (start, end) integer tuple."""
    if isinstance(line, int):
        if line < 1:
            raise ValueError(f"Line number must be >= 1, got {line}")
        return line, line
    if isinstance(line, str):
        if "-" in line:
            parts = line.split("-")
            if len(parts) != 2:
                raise ValueError(f"Invalid line range format: '{line}'")
            try:
                start = int(parts[0].strip())
                end = int(parts[1].strip())
            except ValueError:
                raise ValueError(f"Invalid line range format: '{line}'")
            if start < 1 or end < 1:
                raise ValueError(f"Line numbers in range must be >= 1, got '{line}'")
            if start > end:
                raise ValueError(f"Range start must be <= end, got '{line}'")
            return start, end
        else:
            try:
                val = int(line.strip())
            except ValueError:
                raise ValueError(f"Invalid line number format: '{line}'")
            if val < 1:
                raise ValueError(f"Line number must be >= 1, got '{line}'")
            return val, val
    raise TypeError(f"Unsupported line type: {type(line)} for value '{line}'")

def validate_schema(entries_path, reports_path=None):
    """Validate entries.jsonl and reports.jsonl against SCHEMA.md constraints."""
    errors = []
    reports = {}
    if reports_path and os.path.exists(reports_path):
        with open(reports_path, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rep = json.loads(line)
                    report_id = rep.get("report_id")
                    if report_id:
                        reports[report_id] = rep
                except Exception as e:
                    errors.append(f"reports.jsonl line {idx}: Failed to parse JSON: {e}")

    entry_ids = set()
    report_to_entries = {}

    with open(entries_path, "r", encoding="utf-8") as f:
        for idx, line_str in enumerate(f, 1):
            line_str = line_str.strip()
            if not line_str:
                continue
            try:
                entry = json.loads(line_str)
            except Exception as e:
                errors.append(f"{entries_path} line {idx}: Failed to parse JSON: {e}")
                continue

            entry_id = entry.get("entry_id")
            if not entry_id:
                errors.append(f"{entries_path} line {idx}: Missing 'entry_id'")
                entry_id = f"unknown-line-{idx}"
            else:
                if entry_id in entry_ids:
                    errors.append(f"{entry_id}: Duplicate entry_id found")
                entry_ids.add(entry_id)

            required_fields = {
                "entry_id": str,
                "report_id": str,
                "source_link": str,
                "vuln_ids": list,
                "origin": str,
                "project": str,
                "repo_url": str,
                "commit": str,
                "vuln_title": str,
                "vuln_category_l1": str,
                "vuln_category_l2": str,
                "entry_point": dict,
                "critical_operation": dict,
                "trace": list,
                "verify": int
            }

            for field, expected_type in required_fields.items():
                if field not in entry:
                    errors.append(f"{entry_id}: Missing required field '{field}'")
                elif not isinstance(entry[field], expected_type):
                    errors.append(f"{entry_id}: Field '{field}' expected type {expected_type.__name__}, got {type(entry[field]).__name__}")

            verify = entry.get("verify")
            if verify is not None and verify not in (0, 1):
                errors.append(f"{entry_id}: 'verify' must be 0 or 1, got {verify}")

            commit = entry.get("commit")
            if commit is not None:
                if not isinstance(commit, str) or len(commit) != 40 or not all(c in "0123456789abcdef" for c in commit):
                    errors.append(f"{entry_id}: 'commit' must be 40 lowercase hex chars, got '{commit}'")

            repo_url = entry.get("repo_url")
            if repo_url is not None:
                if not isinstance(repo_url, str) or not repo_url.startswith("https://github.com/"):
                    errors.append(f"{entry_id}: 'repo_url' must start with 'https://github.com/', got '{repo_url}'")

            origin = entry.get("origin")
            if origin is not None and origin != "GitHub Advisory Database (reviewed)":
                errors.append(f"{entry_id}: 'origin' must be 'GitHub Advisory Database (reviewed)', got '{origin}'")

            report_id = entry.get("report_id")
            source_link = entry.get("source_link")
            if report_id is not None and source_link is not None:
                if not isinstance(report_id, str) or not report_id.startswith("GHSA-") or report_id != report_id.upper():
                    errors.append(f"{entry_id}: 'report_id' must be upper-case and start with 'GHSA-', got '{report_id}'")
                if not isinstance(source_link, str) or "github.com/advisories/" not in source_link or report_id.lower() not in source_link.lower():
                    errors.append(f"{entry_id}: 'source_link' must contain 'github.com/advisories/' and match 'report_id', got '{source_link}'")

            omitted_fields = [
                "description", "human_remark", "pipeline_id", "annotated_by",
                "is_active", "created_at", "generality",
                "detection_type", "ground_truth", "taint_source", "taint_sink",
                "vuln_category_l3"
            ]
            for field in omitted_fields:
                if field in entry:
                    errors.append(f"{entry_id}: Contains forbidden internal field '{field}'")

            def validate_node(node_name, node):
                if not isinstance(node, dict):
                    return
                for fld in ["file", "line", "code"]:
                    if fld not in node:
                        errors.append(f"{entry_id}: Node '{node_name}' is missing '{fld}'")

                if "desc" in node and not isinstance(node["desc"], str):
                    errors.append(f"{entry_id}: Node '{node_name}' field 'desc' must be string, got {type(node['desc']).__name__}")

                line_val = node.get("line")
                if line_val is not None:
                    try:
                        start, end = parse_line(line_val)
                        if start < 1 or end < 1:
                            errors.append(f"{entry_id}: Node '{node_name}' line number must be >= 1, got {line_val}")
                        if start > end:
                            errors.append(f"{entry_id}: Node '{node_name}' line range start must be <= end, got {line_val}")
                    except Exception as e:
                        errors.append(f"{entry_id}: Node '{node_name}' line value is invalid: {e}")

            if isinstance(entry.get("entry_point"), dict):
                validate_node("entry_point", entry["entry_point"])
            if isinstance(entry.get("critical_operation"), dict):
                validate_node("critical_operation", entry["critical_operation"])

            trace = entry.get("trace")
            if isinstance(trace, list):
                for t_idx, t_node in enumerate(trace):
                    if not isinstance(t_node, dict):
                        errors.append(f"{entry_id}: trace[{t_idx}] is not an object")
                    else:
                        validate_node(f"trace[{t_idx}]", t_node)

            if report_id:
                if report_id not in report_to_entries:
                    report_to_entries[report_id] = []
                report_to_entries[report_id].append(entry_id)

    if reports:
        for r_id, rep in reports.items():
            if r_id not in report_to_entries:
                errors.append(f"report {r_id}: Found in reports.jsonl but has no corresponding entries in entries.jsonl")
            else:
                rep_entry_ids = sorted(rep.get("entry_ids", []))
                actual_entry_ids = sorted(report_to_entries[r_id])
                if rep_entry_ids != actual_entry_ids:
                    errors.append(f"report {r_id}: 'entry_ids' in reports.jsonl ({rep_entry_ids}) does not match actual entries ({actual_entry_ids})")

        for r_id in report_to_entries:
            if r_id not in reports:
                errors.append(f"report {r_id}: Found in entries.jsonl but has no corresponding report in reports.jsonl")

    return errors

def main():
    parser = argparse.ArgumentParser(
        description="Detect and clean trace duplicate nodes and sequential order anomalies in VulnGym entries."
    )
    parser.add_argument(
        "-i", "--input",
        default="data/entries.jsonl",
        help="Path to the input JSONL file (default: data/entries.jsonl)"
    )
    parser.add_argument(
        "-o", "--output",
        default="data/entries.trace_fixed.jsonl",
        help="Path to the output fixed JSONL file (default: data/entries.trace_fixed.jsonl)"
    )
    parser.add_argument(
        "--log-csv",
        default="reports/trace_fix_log.csv",
        help="Path to the output CSV modification log (default: reports/trace_fix_log.csv)"
    )
    parser.add_argument(
        "--log-json",
        default="reports/trace_fix_log.json",
        help="Path to the output JSON modification log (default: reports/trace_fix_log.json)"
    )
    parser.add_argument(
        "--mode",
        choices=["conservative", "repair"],
        default="conservative",
        help="Order anomaly handling mode. 'conservative' only logs. 'repair' deletes anomalies and logs. (default: conservative)"
    )
    parser.add_argument(
        "--verify-filter",
        choices=["0", "1", "all"],
        default="0",
        help="Filter which entries to process based on their verify flag. (default: 0)"
    )
    parser.add_argument(
        "--delete-after-co",
        action="store_true",
        help="If set, 'after critical operation' anomalies will be deleted under repair mode instead of being retained."
    )
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"Error: Input file '{args.input}' does not exist.", file=sys.stderr)
        sys.exit(1)

    # Ensure target output directories exist
    for path in [args.output, args.log_csv, args.log_json]:
        dirname = os.path.dirname(path)
        if dirname and not os.path.exists(dirname):
            os.makedirs(dirname, exist_ok=True)

    # Validate input schema
    print(f"Scanning input file schema: {args.input}...")
    input_reports_path = os.path.join(os.path.dirname(args.input), "reports.jsonl")
    input_schema_errors = validate_schema(args.input, input_reports_path if os.path.exists(input_reports_path) else None)
    if input_schema_errors:
        print(f"Warning: Found {len(input_schema_errors)} schema errors in input file '{args.input}':", file=sys.stderr)
        for err in input_schema_errors[:10]:
            print(f"  - {err}", file=sys.stderr)
        if len(input_schema_errors) > 10:
            print(f"  - ... and {len(input_schema_errors) - 10} more.", file=sys.stderr)
    else:
        print("Input file schema is 100% valid according to SCHEMA.md.")

    # Statistics counters
    stats = {
        "processed_entries": 0,
        "duplicates_merged": 0,
        "desc_sync_count": 0,
        "before_ep_detected": 0,
        "after_co_detected": 0,
        "nodes_deleted": 0,
        "retained_for_review": 0
    }

    logs = []
    output_lines = []

    with open(args.input, "r", encoding="utf-8") as f:
        for idx, line_str in enumerate(f, 1):
            if not line_str.strip():
                continue
            entry = json.loads(line_str)
            entry_id = entry.get("entry_id", f"unknown-line-{idx}")
            verify = entry.get("verify")

            # Check if this entry should be checked/modified
            should_process = False
            if args.verify_filter == "all":
                should_process = True
            elif args.verify_filter == "0" and verify == 0:
                should_process = True
            elif args.verify_filter == "1" and verify == 1:
                should_process = True

            if not should_process:
                # Write back unchanged
                output_lines.append(json.dumps(entry, ensure_ascii=False, sort_keys=True))
                continue

            stats["processed_entries"] += 1
            ep = entry.get("entry_point")
            co = entry.get("critical_operation")
            trace = entry.get("trace", [])

            if not ep or not co:
                output_lines.append(json.dumps(entry, ensure_ascii=False))
                continue

            ep_file = ep["file"]
            co_file = co["file"]
            try:
                ep_start, ep_end = parse_line(ep["line"])
                co_start, co_end = parse_line(co["line"])
            except Exception as ex:
                print(f"Warning: Failed to parse lines for entry {entry_id}: {ex}", file=sys.stderr)
                output_lines.append(json.dumps(entry, ensure_ascii=False))
                continue

            # 1. Deduplicate trace nodes
            seen_nodes = {} # key -> index in deduped_trace
            deduped_trace = []
            
            for t_idx, t_node in enumerate(trace):
                t_file = t_node.get("file")
                t_line = t_node.get("line")
                t_code = t_node.get("code")
                t_desc = t_node.get("desc", "")
                
                # Check for absolute similarity key
                key = (t_file, str(t_line), t_code)
                if key in seen_nodes:
                    stats["duplicates_merged"] += 1
                    first_idx = seen_nodes[key]
                    prev_node = deduped_trace[first_idx]
                    prev_desc = prev_node.get("desc", "")
                    
                    # Determine if adjustment is needed
                    if t_desc and t_desc.strip():
                        if not prev_desc or not prev_desc.strip():
                            prev_node["desc"] = t_desc
                            stats["desc_sync_count"] += 1
                            logs.append({
                                "entry_id": entry_id,
                                "field_path": f"trace[{first_idx}].desc",
                                "content_before": prev_desc,
                                "content_after": t_desc,
                                "reason": f"Copied missing description from duplicate trace node at original index {t_idx}."
                            })
                        elif t_desc.strip() != prev_desc.strip():
                            # If not substrings of each other, merge them
                            if t_desc.strip() in prev_desc.strip():
                                pass
                            elif prev_desc.strip() in t_desc.strip():
                                prev_node["desc"] = t_desc
                                stats["desc_sync_count"] += 1
                                logs.append({
                                    "entry_id": entry_id,
                                    "field_path": f"trace[{first_idx}].desc",
                                    "content_before": prev_desc,
                                    "content_after": t_desc,
                                    "reason": f"Updated description to the more comprehensive one from original index {t_idx}."
                                })
                            else:
                                merged_desc = prev_desc.strip() + " | " + t_desc.strip()
                                prev_node["desc"] = merged_desc
                                stats["desc_sync_count"] += 1
                                logs.append({
                                    "entry_id": entry_id,
                                    "field_path": f"trace[{first_idx}].desc",
                                    "content_before": prev_desc,
                                    "content_after": merged_desc,
                                    "reason": f"Merged differing descriptions from duplicate node at original index {t_idx}."
                                })
                    # Skip duplicate candidate from final list
                    continue
                else:
                    seen_nodes[key] = len(deduped_trace)
                    # Use a copy of the node to avoid mutating original structure in-place
                    deduped_trace.append(t_node.copy())

            # 2. Detect sequential anomalies
            repaired_trace = []
            for t_idx, t_node in enumerate(deduped_trace):
                t_file = t_node.get("file")
                t_line = t_node.get("line")
                try:
                    t_start, t_end = parse_line(t_line)
                except Exception as ex:
                    print(f"Warning: Failed to parse trace line for entry {entry_id} at index {t_idx}: {ex}", file=sys.stderr)
                    repaired_trace.append(t_node)
                    continue

                is_before_ep = False
                is_after_co = False
                if ep_file == co_file:
                    min_bound = min(ep_start, co_start)
                    max_bound = max(ep_end, co_end)
                    if t_file == ep_file:
                        if t_end < min_bound:
                            is_before_ep = True
                        elif t_start > max_bound:
                            is_after_co = True
                else:
                    if t_file == ep_file and t_end < ep_start:
                        is_before_ep = True
                    elif t_file == co_file and t_start > co_end:
                        is_after_co = True

                if is_before_ep:
                    stats["before_ep_detected"] += 1
                    if args.mode == "repair":
                        stats["nodes_deleted"] += 1
                        logs.append({
                            "entry_id": entry_id,
                            "field_path": f"trace[{t_idx}]",
                            "content_before": t_node,
                            "content_after": None,
                            "reason": f"Deleted trace node (line {t_line} < entry_point line {ep['line']})."
                        })
                        # Skip adding this node to repaired_trace
                        continue
                    else:
                        stats["retained_for_review"] += 1
                        logs.append({
                            "entry_id": entry_id,
                            "field_path": f"trace[{t_idx}]",
                            "content_before": t_node,
                            "content_after": t_node,
                            "reason": f"Detected trace node before entry_point (line {t_line} < entry_point line {ep['line']}), kept in conservative mode."
                        })
                        repaired_trace.append(t_node)

                elif is_after_co:
                    stats["after_co_detected"] += 1
                    if args.mode == "repair" and args.delete_after_co:
                        stats["nodes_deleted"] += 1
                        logs.append({
                            "entry_id": entry_id,
                            "field_path": f"trace[{t_idx}]",
                            "content_before": t_node,
                            "content_after": None,
                            "reason": f"Deleted trace node (line {t_line} > critical_operation line {co['line']})."
                        })
                        # Skip adding this node
                        continue
                    else:
                        stats["retained_for_review"] += 1
                        logs.append({
                            "entry_id": entry_id,
                            "field_path": f"trace[{t_idx}]",
                            "content_before": t_node,
                            "content_after": t_node,
                            "reason": f"Detected trace node after critical_operation (line {t_line} > critical_operation line {co['line']}), retained for manual review."
                        })
                        repaired_trace.append(t_node)
                else:
                    repaired_trace.append(t_node)

            # Update trace in entry object
            entry["trace"] = repaired_trace
            output_lines.append(json.dumps(entry, ensure_ascii=False, sort_keys=True))

    # Write modified entries
    with open(args.output, "w", encoding="utf-8") as f:
        for out_line in output_lines:
            f.write(out_line + "\n")

    # Validate output schema
    print(f"Scanning output file schema: {args.output}...")
    output_reports_path = os.path.join(os.path.dirname(args.output), "reports.jsonl")
    if not os.path.exists(output_reports_path):
        output_reports_path = os.path.join(os.path.dirname(args.input), "reports.jsonl")
    output_schema_errors = validate_schema(args.output, output_reports_path if os.path.exists(output_reports_path) else None)
    if output_schema_errors:
        print(f"Error: Output file '{args.output}' does not satisfy SCHEMA.md constraints!", file=sys.stderr)
        for err in output_schema_errors[:10]:
            print(f"  - {err}", file=sys.stderr)
        sys.exit(1)
    else:
        print("Output file schema is 100% valid according to SCHEMA.md.")

    # Write logs to JSON
    with open(args.log_json, "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=2, ensure_ascii=False)

    # Write logs to CSV
    with open(args.log_csv, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Entry ID", "Field Path", "Content Before", "Content After", "Reason"])
        for lg in logs:
            writer.writerow([
                lg["entry_id"],
                lg["field_path"],
                json.dumps(lg["content_before"], ensure_ascii=False) if isinstance(lg["content_before"], dict) else lg["content_before"],
                json.dumps(lg["content_after"], ensure_ascii=False) if isinstance(lg["content_after"], dict) else lg["content_after"],
                lg["reason"]
            ])

    # Print detection report to stdout
    print("\n" + "=" * 40)
    print("      VULNGYM TRACE CLEANUP REPORT      ")
    print("=" * 40)
    print(f"Mode:                   {args.mode.upper()}")
    print(f"Verify Filter:          {args.verify_filter}")
    print(f"Processed Entries:      {stats['processed_entries']}")
    print(f"Duplicate Nodes Merged: {stats['duplicates_merged']}")
    print(f"Description Syncs:      {stats['desc_sync_count']}")
    print(f"Before EP Anomalies:    {stats['before_ep_detected']}")
    print(f"After CO Anomalies:     {stats['after_co_detected']}")
    print(f"Trace Nodes Deleted:    {stats['nodes_deleted']}")
    print(f"Retained for Review:    {stats['retained_for_review']}")
    print(f"Input Schema Errors:    {len(input_schema_errors)}")
    print(f"Output Schema Errors:   {len(output_schema_errors)}")
    print("-" * 40)
    print(f"Fixed File Written to:  {args.output}")
    print(f"CSV Log Written to:     {args.log_csv}")
    print(f"JSON Log Written to:    {args.log_json}")
    print("=" * 40 + "\n")

if __name__ == "__main__":
    main()
