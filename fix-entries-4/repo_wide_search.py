"""
Issue #4 第三优先级兜底：全仓库搜索 (whole-repo search)。

对 needs_human.csv 中"±5 行邻域搜索"和"全文件搜索"都失败的节点，
在对应 (repo, commit) 的完整仓库范围内（而不仅仅是节点自身声明的 file）
搜索是否存在唯一匹配，从而发现"文件路径本身写错、代码其实在别的文件里"的情况。

做法：对 needs_human.csv 里出现的每个 (repo_url, commit) 组合，用
`git fetch --depth 1 origin <commit> && git checkout FETCH_HEAD` 拉取该
commit 的完整源码快照到 repos/ 下（只拉一次，按 commit 缓存），然后在整
个工作区范围内做逐文件的精确匹配搜索。

依赖：本机可执行 git，且能访问 github.com（不仅仅是 raw.githubusercontent.com）。

用法：先运行 fix_entries.py 产出 entries.fixed.jsonl / fix_diff.csv /
needs_human.csv，再运行本脚本，会在原基础上继续修正 needs_human.csv 里能
在全仓库范围内唯一定位到的节点，并把结果追加进 fix_diff.csv。
"""
import json, re, csv, os, subprocess, sys

def norm(s):
    return "\n".join(l.strip() for l in s.strip("\n").split("\n"))

def strip_trailing_comment(line):
    m = re.match(r'^(.*?)(\s*//.*|\s*#\s*[一-鿿].*)$', line)
    if m and m.group(2).strip():
        return m.group(1).rstrip()
    return line

def norm_ignore_comment(s):
    return "\n".join(strip_trailing_comment(l.strip()) for l in s.strip("\n").split("\n"))

def parse_line(line):
    if isinstance(line, int):
        return line, line
    a, b = line.split("-")
    return int(a), int(b)

def fmt_line(s, e):
    return s if s == e else f"{s}-{e}"

REPOS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "repos")

def local_dir_for(repo_url, commit):
    owner_repo = repo_url.replace("https://github.com/", "").rstrip("/").replace("/", "_")
    return os.path.join(REPOS_DIR, f"{owner_repo}_{commit[:8]}")

def ensure_clone(repo_url, commit):
    """浅克隆指定 commit 到本地（若已存在则跳过）。返回本地目录绝对路径。"""
    dest = local_dir_for(repo_url, commit)
    if os.path.isdir(os.path.join(dest, ".git")):
        return dest
    os.makedirs(dest, exist_ok=True)
    clone_url = repo_url if repo_url.endswith(".git") else repo_url + ".git"
    subprocess.run(["git", "init", "-q"], cwd=dest, check=True)
    subprocess.run(["git", "remote", "add", "origin", clone_url], cwd=dest, check=True)
    subprocess.run(["git", "fetch", "--depth", "1", "-q", "origin", commit], cwd=dest, check=True)
    subprocess.run(["git", "checkout", "-q", "FETCH_HEAD"], cwd=dest, check=True)
    return dest

SKIP_DIRS = {".git", "node_modules", "dist", "build", ".next", "out", "coverage"}
TEXT_EXT_SKIP = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf", ".eot",
                 ".pdf", ".zip", ".gz", ".lock", ".map", ".min.js"}

def iter_repo_files(repo_dir):
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fn in files:
            ext = os.path.splitext(fn)[1].lower()
            if ext in TEXT_EXT_SKIP:
                continue
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, repo_dir).replace("\\", "/")
            yield rel, full

_file_cache = {}
def read_lines(full_path):
    if full_path in _file_cache:
        return _file_cache[full_path]
    try:
        with open(full_path, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().split("\n")
    except Exception:
        lines = None
    _file_cache[full_path] = lines
    return lines

def search_repo(repo_dir_abs, code, ignore_comment=False):
    """在整个仓库范围内搜索 code 的唯一匹配，返回 [(rel_path, start, end), ...]"""
    n = len(code.split("\n"))
    target = norm_ignore_comment(code) if ignore_comment else norm(code)
    if ignore_comment and target.strip() == "":
        # code 本身整行都是注释（例如标注"此处缺失某校验"的合成节点），
        # 去注释后为空串，若不做保护会与仓库里任意纯注释行"误判匹配"。
        return []
    hits = []
    for rel, full in iter_repo_files(repo_dir_abs):
        lines = read_lines(full)
        if lines is None or len(lines) < n:
            continue
        for s in range(1, len(lines) - n + 2):
            window = "\n".join(lines[s-1:s-1+n])
            cand = norm_ignore_comment(window) if ignore_comment else norm(window)
            if cand == target:
                hits.append((rel, s, s + n - 1))
    return hits

def load_entries(path):
    entries = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            e = json.loads(line)
            entries[e["entry_id"]] = e
    return entries

def get_node(e, field_path):
    if field_path == "entry_point":
        return e["entry_point"]
    if field_path == "critical_operation":
        return e["critical_operation"]
    m = re.match(r"trace\[(\d+)\]", field_path)
    if m:
        return e["trace"][int(m.group(1))]
    raise ValueError(field_path)

def main():
    entries = load_entries("entries.fixed.jsonl")

    needs_human_rows = []
    with open("needs_human.csv", encoding="utf-8") as fh:
        r = csv.DictReader(fh)
        for row in r:
            needs_human_rows.append(row)

    # 按 (repo_url, commit) 去重，逐个克隆一次
    pairs = sorted({(entries[row["entry_id"]]["repo_url"], entries[row["entry_id"]]["commit"])
                    for row in needs_human_rows})
    clone_dirs = {}
    for repo_url, commit in pairs:
        print(f"cloning {repo_url} @ {commit[:8]} ...", file=sys.stderr)
        try:
            clone_dirs[(repo_url, commit)] = ensure_clone(repo_url, commit)
        except subprocess.CalledProcessError as ex:
            print(f"  clone failed: {ex}", file=sys.stderr)
            clone_dirs[(repo_url, commit)] = None

    repo_diff_rows = []
    still_needs_human_rows = []

    for row in needs_human_rows:
        entry_id = row["entry_id"]
        field_path = row["field_path"]
        e = entries[entry_id]
        node = get_node(e, field_path)
        key = (e["repo_url"], e["commit"])
        repo_abs = clone_dirs.get(key)

        if repo_abs is None:
            row["repo_search_result"] = "CLONE_FAILED"
            still_needs_human_rows.append(row)
            continue

        code = node["code"]

        hits = search_repo(repo_abs, code, ignore_comment=False)
        strategy = "FIXED_REPO_SEARCH"
        if not hits:
            hits = search_repo(repo_abs, code, ignore_comment=True)
            strategy = "FIXED_REPO_SEARCH_COMMENT"

        if len(hits) == 1:
            rel, s, en = hits[0]
            new_line = fmt_line(s, en)
            old_file = node["file"]
            old_line = row["line"]
            repo_diff_rows.append([entry_id, field_path, old_file, old_line, rel, new_line, strategy])
            node["file"] = rel
            node["line"] = new_line if s != en else s
            row["repo_search_result"] = f"{strategy}:{rel}:{new_line}"
        elif len(hits) > 1:
            row["repo_search_result"] = f"MULTI_HIT_REPO_WIDE:{len(hits)}"
            still_needs_human_rows.append(row)
        else:
            row["repo_search_result"] = "STILL_NOT_FOUND_REPO_WIDE"
            still_needs_human_rows.append(row)

    with open("entries.fixed.jsonl", "w", encoding="utf-8", newline="\n") as f:
        for entry_id, e in entries.items():
            f.write(json.dumps(e, ensure_ascii=False) + "\n")

    with open("fix_diff.csv", "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerows(repo_diff_rows)

    with open("needs_human.csv", "w", newline="", encoding="utf-8") as f:
        fieldnames = ["entry_id", "field_path", "file", "line", "reason", "source_url"]
        w = csv.writer(f)
        w.writerow(fieldnames)
        for row in still_needs_human_rows:
            w.writerow([row[k] for k in fieldnames])

    with open("repo_wide_search_log.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["entry_id", "field_path", "file", "line", "reason", "source_url", "repo_search_result"])
        for row in needs_human_rows:
            w.writerow([row.get(k, "") for k in ["entry_id", "field_path", "file", "line", "reason", "source_url", "repo_search_result"]])

    print(f"全仓库搜索新修复: {len(repo_diff_rows)} 处")
    print(f"仍需人工复核: {len(still_needs_human_rows)} 处")

if __name__ == "__main__":
    main()
