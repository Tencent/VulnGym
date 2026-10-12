import json, urllib.request, re, csv

def norm(s):
    return "\n".join(l.strip() for l in s.strip("\n").split("\n"))

def strip_trailing_comment(line):
    m = re.match(r'^(.*?)(\s*//.*|\s*#\s*[\u4e00-\u9fff].*)$', line)
    if m and m.group(2).strip():
        return m.group(1).rstrip()
    return line

def norm_ignore_comment(s):
    return "\n".join(strip_trailing_comment(l.strip()) for l in s.strip("\n").split("\n"))

entries = []
with open("../data/entries.jsonl", encoding="utf-8") as fh:
    for line in fh:
        entries.append(json.loads(line))

filecache = {}
def fetch_raw(repo_url, commit, path):
    key = (repo_url, commit, path)
    if key in filecache:
        return filecache[key]
    owner_repo = repo_url.replace("https://github.com/", "").rstrip("/")
    url = f"https://raw.githubusercontent.com/{owner_repo}/{commit}/{path}"
    try:
        with urllib.request.urlopen(url, timeout=15) as r:
            content = r.read().decode("utf-8", errors="replace")
        lines = content.split("\n")
    except Exception:
        lines = None
    filecache[key] = lines
    return lines

def parse_line(line):
    if isinstance(line, int):
        return line, line
    a, b = line.split("-")
    return int(a), int(b)

def fmt_line(s, e):
    return s if s == e else f"{s}-{e}"

def classify_and_fix(node, lines):
    code = node["code"]
    n = len(code.split("\n"))
    orig_start, orig_end = parse_line(node["line"])

    if orig_start - 1 + n <= len(lines):
        cand = "\n".join(lines[orig_start-1:orig_start-1+n])
        if norm(cand) == norm(code):
            return ("OK", None, None)
        if norm_ignore_comment(cand) == norm_ignore_comment(code):
            return ("ANNOTATOR_COMMENT_ONLY", None, None)

    matches = [s for s in range(max(1, orig_start-5), orig_start+6)
               if s-1+n <= len(lines) and norm("\n".join(lines[s-1:s-1+n])) == norm(code)]
    if len(matches) == 1:
        return ("FIXED_NEARBY", matches[0], matches[0]+n-1)
    elif len(matches) > 1:
        return ("MULTI_HIT", None, None)

    matches_c = [s for s in range(max(1, orig_start-5), orig_start+6)
                 if s-1+n <= len(lines) and norm_ignore_comment("\n".join(lines[s-1:s-1+n])) == norm_ignore_comment(code)]
    if len(matches_c) == 1:
        return ("FIXED_NEARBY_COMMENT", matches_c[0], matches_c[0]+n-1)

    matches2 = [s for s in range(1, len(lines)-n+2) if norm("\n".join(lines[s-1:s-1+n])) == norm(code)]
    if len(matches2) == 1:
        return ("FIXED_WHOLE_FILE", matches2[0], matches2[0]+n-1)
    elif len(matches2) > 1:
        return ("MULTI_HIT", None, None)

    return ("NEEDS_HUMAN", None, None)

fix_diff_rows = []
needs_human_rows = []
fixed_count = 0
from collections import Counter
debug_counter = Counter()

for e in entries:
    nodes = [("entry_point", e["entry_point"]), ("critical_operation", e["critical_operation"])]
    nodes += [(f"trace[{i}]", t) for i, t in enumerate(e["trace"])]
    for path, node in nodes:
        lines = fetch_raw(e["repo_url"], e["commit"], node["file"])
        if lines is None:
            debug_counter["FETCH_FAILED"] += 1
            needs_human_rows.append([e["entry_id"], path, node["file"], node["line"], "FETCH_FAILED", ""])
            continue
        outcome, s, en = classify_and_fix(node, lines)
        debug_counter[outcome] += 1
        if outcome in ("FIXED_NEARBY", "FIXED_NEARBY_COMMENT", "FIXED_WHOLE_FILE"):
            new_line = fmt_line(s, en)
            fix_diff_rows.append([e["entry_id"], path, node["file"], node["line"], node["file"], new_line, outcome])
            node["line"] = new_line if s != en else s
            fixed_count += 1
        elif outcome == "NEEDS_HUMAN" or outcome == "MULTI_HIT":
            needs_human_rows.append([e["entry_id"], path, node["file"], node["line"], outcome, e["repo_url"] + "/blob/" + e["commit"] + "/" + node["file"]])
        # OK / ANNOTATOR_COMMENT_ONLY: leave untouched

print("DEBUG distribution:", dict(debug_counter))

with open("entries.fixed.jsonl", "w", encoding="utf-8", newline="\n") as f:
    for e in entries:
        f.write(json.dumps(e, ensure_ascii=False) + "\n")

with open("fix_diff.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["entry_id", "field_path", "file", "old_line", "new_file", "new_line", "fix_strategy"])
    w.writerows(fix_diff_rows)

with open("needs_human.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["entry_id", "field_path", "file", "line", "reason", "source_url"])
    w.writerows(needs_human_rows)

print(f"自动修复: {fixed_count} 处")
print(f"进入人工复核: {len(needs_human_rows)} 处")
print(f"输出文件: entries.fixed.jsonl, fix_diff.csv, needs_human.csv")
