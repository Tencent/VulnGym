from config import (
    ENTRIES_JSONL_FILE_PATH,
    FIXED_JSONL_OUTPUT_PATH,
    NEEDS_HUMAN_CSV_PATH,
    FIX_DIFF_CSV_PATH,
    LINE_SEARCH_OFFSET,
    USE_GHPROXY,
    TIMEOUT,
    CHROME_USER_AGENT,
    READ_MAX_LINES,
    READ_START_LINE,
    READ_END_LINE,
    ENABLE_WHOLE_REPO_SCAN,
    MAX_REPO_SCAN_FILES,
    ENABLE_FILE_CACHE
)

import json
import requests
import urllib3
import re
import csv
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
HEADERS = {"User-Agent": CHROME_USER_AGENT}

# 全局文件缓存 key=完整raw链接  value=(content, lines)
file_cache = {}


def extract_info(node: dict) -> dict:
    if not isinstance(node, dict):
        return {"file": None, "line": None, "code": None, "desc": None}
    return {
        "file": node.get("file", None),
        "line": node.get("line", None),
        "code": node.get("code", None),
        "desc": node.get("desc", None)
    }


def parse_line_range(raw_line_val):
    if raw_line_val is None:
        return None, None
    line_str = str(raw_line_val).strip()
    if line_str.isdigit():
        num = int(line_str)
        return num, num
    if "-" in line_str:
        parts = line_str.split("-")
        if len(parts) == 2:
            s_str = parts[0].strip()
            e_str = parts[1].strip()
            if s_str.isdigit() and e_str.isdigit():
                s = int(s_str)
                e = int(e_str)
                return min(s, e), max(s, e)
    return None, None


def normalize_text(text: str, loose_match: bool = False) -> str:
    if text is None:
        return ""
    unified = text.replace("\r\n", "\n").replace("\r", "\n")
    if loose_match:
        unified = re.sub(r"[\t ]+", " ", unified)
    return unified.strip()


def build_raw_link(repo_url: str, commit_hash: str, file_path: str) -> str:
    if not repo_url or not commit_hash or not file_path:
        return ""
    repo_part = repo_url.replace("https://github.com/", "").strip("/")
    raw_link = f"https://raw.githubusercontent.com/{repo_part}/{commit_hash}/{file_path}"
    if USE_GHPROXY:
        raw_link = f"https://mirror.ghproxy.com/{raw_link}"
    return raw_link


def download_file(repo_url: str, commit: str, file_path: str):
    url = build_raw_link(repo_url, commit, file_path)
    cache_key = url

    # 命中缓存直接返回，不再重复下载
    if ENABLE_FILE_CACHE and cache_key in file_cache:
        return file_cache[cache_key][0], file_cache[cache_key][1], None

    try:
        resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False, stream=True)
        resp.raise_for_status()
        content = resp.text
        lines = content.splitlines()
        if ENABLE_FILE_CACHE:
            file_cache[cache_key] = (content, lines)
        return content, lines, None
    except requests.exceptions.Timeout:
        return "", [], f"下载超时{TIMEOUT}s"
    except requests.exceptions.ConnectionError:
        return "", [], "连接失败"
    except Exception as e:
        return "", [], str(e)


def search_code_in_file(file_lines: list, target_loose: str) -> list:
    hit_lines = []
    total_line_cnt = len(file_lines)
    target_lines = target_loose.split("\n")
    target_len = len(target_lines)
    if target_len == 0:
        return hit_lines

    for start_idx in range(total_line_cnt - target_len + 1):
        window_raw = "\n".join(file_lines[start_idx: start_idx + target_len])
        window_loose = normalize_text(window_raw, loose_match=True)
        if window_loose == target_loose:
            hit_lines.append(start_idx + 1)
    return hit_lines


def repo_list_all_files(repo_url: str, commit: str):
    owner_repo = repo_url.replace("https://github.com/", "").strip("/")
    api_url = f"https://api.github.com/repos/{owner_repo}/git/trees/{commit}?recursive=1"
    if USE_GHPROXY:
        api_url = f"https://mirror.ghproxy.com/{api_url}"
    try:
        resp = requests.get(api_url, headers=HEADERS, timeout=TIMEOUT, verify=False)
        resp.raise_for_status()
        tree_data = resp.json()
        all_files = []
        for item in tree_data["tree"]:
            if item["type"] == "blob":
                all_files.append(item["path"])
                # 限制最大文件数量，防止超大仓库卡死
                if len(all_files) >= MAX_REPO_SCAN_FILES:
                    print(f"仓库文件过多，已达到最大遍历上限{MAX_REPO_SCAN_FILES}，截断文件列表")
                    break
        return all_files, None
    except Exception as e:
        return [], str(e)


def three_stage_repair(original_file, original_line_raw, repo_url, commit, local_code):
    target_loose = normalize_text(local_code, loose_match=True)
    if not target_loose:
        return False, original_file, original_line_raw, [], "待匹配code为空", ""

    start_orig, end_orig = parse_line_range(original_line_raw)
    file_content, file_lines, err = download_file(repo_url, commit, original_file)
    if err:
        return False, original_file, original_line_raw, [], f"下载原文件失败：{err}", ""
    total_file_lines = len(file_lines)

    offset = LINE_SEARCH_OFFSET
    search_s = max(1, start_orig - offset)
    search_e = min(total_file_lines, end_orig + offset)
    sub_lines = file_lines[search_s - 1: search_e]
    hit_stage1 = search_code_in_file(sub_lines, target_loose)
    hit_stage1_global = [x + search_s - 1 for x in hit_stage1]
    if len(hit_stage1_global) == 1:
        hit_line = hit_stage1_global[0]
        return True, original_file, hit_line, hit_stage1_global, "", "阶段1±5行区间唯一命中修复"

    hit_stage2 = search_code_in_file(file_lines, target_loose)
    if len(hit_stage2) == 1:
        hit_line = hit_stage2[0]
        return True, original_file, hit_line, hit_stage2, "", "阶段2当前文件全量检索唯一命中修复"

    # 新增：总开关控制是否进入全仓库遍历（防卡死核心）
    if not ENABLE_WHOLE_REPO_SCAN:
        return False, original_file, original_line_raw, [], "已关闭全仓库检索，仅检索当前文件", ""

    all_files, list_err = repo_list_all_files(repo_url, commit)
    if list_err:
        return False, original_file, original_line_raw, [], f"仓库文件列表获取失败：{list_err}", ""
    repo_hits = []
    for fpath in all_files:
        f_cont, f_lines, f_err = download_file(repo_url, commit, fpath)
        if f_err:
            # 单个文件下载失败直接跳过，不阻塞循环整体
            continue
        hits = search_code_in_file(f_lines, target_loose)
        for ln in hits:
            repo_hits.append({"file": fpath, "line": ln})
    if len(repo_hits) == 1:
        hit_item = repo_hits[0]
        return True, hit_item["file"], hit_item["line"], repo_hits, "", "阶段3全仓库检索唯一命中，修正文件+行号"

    if len(repo_hits) == 0:
        return False, original_file, original_line_raw, [], "三级检索全程无宽松匹配命中", ""
    else:
        return False, original_file, original_line_raw, repo_hits, f"命中{len(repo_hits)}处，多匹配无法自动修复", ""


def write_human_csv(csv_path, rows):
    header = [
        "entry_id(JSON物理行号)", "节点字段路径", "原始file", "原始line", "原始desc",
        "repo_url", "commit", "无法修复原因", "命中明细"
    ]
    try:
        with open(csv_path, "a", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=header)
            if f.tell() == 0:
                writer.writeheader()
            writer.writerows(rows)
    except Exception as e:
        print(f"needs_human.csv写入失败：{e}")


def write_fix_diff_csv(csv_path, rows):
    header = [
        "entry_id(JSON物理行号)", "节点字段路径",
        "old_file", "old_line", "old_desc",
        "new_file", "new_line", "new_desc",
        "修复策略说明"
    ]
    try:
        with open(csv_path, "a", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=header)
            if f.tell() == 0:
                writer.writeheader()
            writer.writerows(rows)
    except Exception as e:
        print(f"fix_diff.csv写入失败：{e}")


def process_single_node(
    node_path: str, node_meta: dict, repo_url: str, commit: str, entry_id: int,
    human_list: list, diff_list: list
):
    file_orig = node_meta["file"]
    line_orig = node_meta["line"]
    code_local = node_meta["code"]
    desc_orig = node_meta["desc"]

    if not repo_url or not commit or not file_orig or code_local is None:
        human_list.append({
            "entry_id(JSON物理行号)": entry_id,
            "节点字段路径": node_path,
            "原始file": file_orig,
            "原始line": line_orig,
            "原始desc": desc_orig,
            "repo_url": repo_url,
            "commit": commit,
            "无法修复原因": "必填字段file/code/repo/commit缺失",
            "命中明细": ""
        })
        return node_meta

    s_orig, e_orig = parse_line_range(line_orig)
    match_ok = False
    url = build_raw_link(repo_url, commit, file_orig)
    try:
        resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False)
        resp.raise_for_status()
        all_lines = resp.text.splitlines()
        s_idx = s_orig - 1
        e_idx = e_orig - 1
        online_raw = "\n".join(all_lines[s_idx: e_idx+1])
        s_strict = normalize_text(code_local, False)
        o_strict = normalize_text(online_raw, False)
        s_loose = normalize_text(code_local, True)
        o_loose = normalize_text(online_raw, True)
        if o_strict == s_strict or o_loose == s_loose:
            match_ok = True
    except Exception:
        pass
    if match_ok:
        return node_meta

    fix_ok, new_file, new_line, hit_info, fail_reason, fix_strategy = three_stage_repair(
        file_orig, line_orig, repo_url, commit, code_local
    )
    if fix_ok:
        new_node = {
            "file": new_file,
            "line": new_line,
            "code": code_local,
            "desc": desc_orig
        }
        diff_list.append({
            "entry_id(JSON物理行号)": entry_id,
            "节点字段路径": node_path,
            "old_file": file_orig,
            "old_line": line_orig,
            "old_desc": desc_orig,
            "new_file": new_file,
            "new_line": new_line,
            "new_desc": desc_orig,
            "修复策略说明": fix_strategy
        })
        return new_node
    else:
        human_list.append({
            "entry_id(JSON物理行号)": entry_id,
            "节点字段路径": node_path,
            "原始file": file_orig,
            "原始line": line_orig,
            "原始desc": desc_orig,
            "repo_url": repo_url,
            "commit": commit,
            "无法修复原因": fail_reason,
            "命中明细": json.dumps(hit_info, ensure_ascii=False)
        })
        return node_meta


def full_batch_pipeline(cmd_start=None, cmd_end=None, cmd_max=None):
    global file_cache
    # 每次完整运行清空缓存，避免上次残留脏数据
    file_cache = {}

    use_range = False
    use_max = False
    start = 0
    end = 0
    max_n = 0

    if cmd_start is not None and cmd_end is not None and cmd_start > 0 and cmd_end >= cmd_start:
        start, end = cmd_start, cmd_end
        use_range = True
    elif cmd_max is not None and cmd_max >= 0:
        max_n = cmd_max
        use_max = True
    else:
        if READ_START_LINE > 0 and READ_END_LINE >= READ_START_LINE:
            start, end = READ_START_LINE, READ_END_LINE
            use_range = True
        else:
            max_n = READ_MAX_LINES
            use_max = True if max_n > 0 else False

    final_fix_jsonl = []
    human_csv_rows = []
    fix_diff_csv_rows = []
    entry_id = 1

    with open(ENTRIES_JSONL_FILE_PATH, "r", encoding="utf-8") as f_in:
        for raw_ln in f_in:
            if use_range:
                if entry_id < start:
                    entry_id += 1
                    continue
                if entry_id > end:
                    print(f"到达区间尾行{end}，终止读取")
                    break
            if use_max and entry_id > max_n:
                print(f"到达前{max_n}行上限，终止读取")
                break

            raw_ln = raw_ln.strip()
            if not raw_ln:
                entry_id += 1
                continue
            try:
                line_data = json.loads(raw_ln)
            except json.JSONDecodeError:
                print(f"entry_id {entry_id} JSON格式损坏，跳过")
                entry_id += 1
                continue

            repo = line_data.get("repo_url", "")
            commit = line_data.get("commit", "")
            new_line_data = line_data.copy()

            entry_raw = line_data.get("entry_point", {})
            entry_meta = extract_info(entry_raw)
            new_entry = process_single_node(
                node_path="entry_point",
                node_meta=entry_meta,
                repo_url=repo,
                commit=commit,
                entry_id=entry_id,
                human_list=human_csv_rows,
                diff_list=fix_diff_csv_rows
            )
            new_line_data["entry_point"] = new_entry

            crit_raw = line_data.get("critical_operation", {})
            crit_meta = extract_info(crit_raw)
            new_crit = process_single_node(
                node_path="critical_operation",
                node_meta=crit_meta,
                repo_url=repo,
                commit=commit,
                entry_id=entry_id,
                human_list=human_csv_rows,
                diff_list=fix_diff_csv_rows
            )
            new_line_data["critical_operation"] = new_crit

            trace_new = []
            trace_list = line_data.get("trace", [])
            if isinstance(trace_list, list):
                for idx, trace_item in enumerate(trace_list):
                    trace_meta = extract_info(trace_item)
                    path_name = f"trace[{idx}]"
                    fixed_trace_item = process_single_node(
                        node_path=path_name,
                        node_meta=trace_meta,
                        repo_url=repo,
                        commit=commit,
                        entry_id=entry_id,
                        human_list=human_csv_rows,
                        diff_list=fix_diff_csv_rows
                    )
                    trace_new.append(fixed_trace_item)
            new_line_data["trace"] = trace_new

            final_fix_jsonl.append(json.dumps(new_line_data, ensure_ascii=False))
            print(f"完成 entry_id {entry_id} 全节点校验处理")
            entry_id += 1

    with open(FIXED_JSONL_OUTPUT_PATH, "w", encoding="utf-8") as f_out:
        for line in final_fix_jsonl:
            f_out.write(line + "\n")

    if human_csv_rows:
        write_human_csv(NEEDS_HUMAN_CSV_PATH, human_csv_rows)
        print(f"人工待处理 {len(human_csv_rows)} 条，写入 {NEEDS_HUMAN_CSV_PATH}")
    if fix_diff_csv_rows:
        write_fix_diff_csv(FIX_DIFF_CSV_PATH, fix_diff_csv_rows)
        print(f"自动修改 {len(fix_diff_csv_rows)} 处，修改明细写入 {FIX_DIFF_CSV_PATH}")

    if use_range:
        print(f"处理区间：{start}~{end}，共处理有效行数 {len(final_fix_jsonl)}")
    elif use_max:
        print(f"处理前{max_n}行，有效行数 {len(final_fix_jsonl)}")
    else:
        print(f"全文件处理完成，有效行数 {len(final_fix_jsonl)}")
    print(f"修复文件输出：{FIXED_JSONL_OUTPUT_PATH}")


if __name__ == "__main__":
    arg1 = None
    arg2 = None
    if len(sys.argv) == 2:
        try:
            arg1 = int(sys.argv[1])
        except ValueError:
            pass
    elif len(sys.argv) == 3:
        try:
            arg1 = int(sys.argv[1])
            arg2 = int(sys.argv[2])
        except ValueError:
            pass

    cmd_s, cmd_e, cmd_m = None, None, None
    if arg1 is not None and arg2 is not None:
        cmd_s, cmd_e = arg1, arg2
    elif arg1 is not None:
        cmd_m = arg1

    full_batch_pipeline(cmd_start=cmd_s, cmd_end=cmd_e, cmd_max=cmd_m)