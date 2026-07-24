from config import (
    ENTRIES_JSONL_FILE_PATH,
    FIXED_JSONL_OUTPUT_PATH,
    NEEDS_HUMAN_CSV_PATH,
    LINE_SEARCH_OFFSET,
    USE_GHPROXY,
    TIMEOUT,
    CHROME_USER_AGENT,
    READ_MAX_LINES,
    READ_START_LINE,
    READ_END_LINE
)

import json
import requests
import urllib3
import re
import csv
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
HEADERS = {"User-Agent": CHROME_USER_AGENT}


def extract_info(node: dict) -> dict:
    if not isinstance(node, dict):
        return {"file": None, "line": None, "line": None, "code": None, "desc": None}
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
    try:
        resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False)
        resp.raise_for_status()
        content = resp.text
        lines = content.splitlines()
        return content, lines, None
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
        return all_files, None
    except Exception as e:
        return [], str(e)


def three_stage_repair(
    original_file: str, original_line_raw, repo_url: str, commit: str, local_code: str
):
    target_loose = normalize_text(local_code, loose_match=True)
    if not target_loose:
        return False, original_file, original_line_raw, [], "待匹配code为空"

    start_orig, end_orig = parse_line_range(original_line_raw)
    file_content, file_lines, err = download_file(repo_url, commit, original_file)
    if err:
        return False, original_file, original_line_raw, [], f"下载原文件失败：{err}"
    total_file_lines = len(file_lines)

    offset = LINE_SEARCH_OFFSET
    search_s = max(1, start_orig - offset)
    search_e = min(total_file_lines, end_orig + offset)
    sub_lines = file_lines[search_s - 1: search_e]
    hit_stage1 = search_code_in_file(sub_lines, target_loose)
    hit_stage1_global = [x + search_s - 1 for x in hit_stage1]
    if len(hit_stage1_global) == 1:
        hit_line = hit_stage1_global[0]
        return True, original_file, hit_line, hit_stage1_global, "阶段1(±5行)唯一命中修复行号"

    hit_stage2 = search_code_in_file(file_lines, target_loose)
    if len(hit_stage2) == 1:
        hit_line = hit_stage2[0]
        return True, original_file, hit_line, hit_stage2, "阶段2(当前全文件)唯一命中修复行号"

    all_files, list_err = repo_list_all_files(repo_url, commit)
    if list_err:
        return False, original_file, original_line_raw, [], f"仓库文件列表获取失败：{list_err}"
    repo_hits = []
    for fpath in all_files:
        f_cont, f_lines, f_err = download_file(repo_url, commit, fpath)
        if f_err:
            continue
        hits = search_code_in_file(f_lines, target_loose)
        for ln in hits:
            repo_hits.append({"file": fpath, "line": ln})
    if len(repo_hits) == 1:
        hit_item = repo_hits[0]
        return True, hit_item["file"], hit_item["line"], repo_hits, "阶段3(全仓库)唯一命中，修正文件+行号"

    if len(repo_hits) == 0:
        return False, original_file, original_line_raw, [], "三级检索全程无任何宽松匹配命中"
    else:
        return False, original_file, original_line_raw, repo_hits, f"检索命中{len(repo_hits)}处，多处匹配无法自动判定"


def write_human_csv(csv_path, rows):
    header = [
        "json全局行号", "节点类型", "原始file", "原始line",
        "repo_url", "commit", "匹配失败原因", "检索命中详情"
    ]
    try:
        with open(csv_path, "a", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=header)
            if f.tell() == 0:
                writer.writeheader()
            writer.writerows(rows)
    except Exception as e:
        print(f"CSV写入异常：{e}")


def process_single_node(node_type: str, node_meta: dict, repo_url: str, commit: str, json_line_no: int, human_list: list):
    file_orig = node_meta["file"]
    line_orig = node_meta["line"]
    code_local = node_meta["code"]
    desc = node_meta["desc"]

    if not repo_url or not commit or not file_orig or code_local is None:
        human_list.append({
            "json全局行号": json_line_no,
            "节点类型": node_type,
            "原始file": file_orig,
            "原始line": line_orig,
            "repo_url": repo_url,
            "commit": commit,
            "匹配失败原因": "基础字段缺失，无法校验修复",
            "检索命中详情": ""
        })
        return node_meta

    s_orig, e_orig = parse_line_range(line_orig)
    url = build_raw_link(repo_url, commit, file_orig)
    match_ok = False
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

    fix_ok, new_file, new_line, hit_info, fix_reason = three_stage_repair(
        file_orig, line_orig, repo_url, commit, code_local
    )
    if fix_ok:
        return {
            "file": new_file,
            "line": new_line,
            "code": code_local,
            "desc": desc
        }
    else:
        human_list.append({
            "json全局行号": json_line_no,
            "节点类型": node_type,
            "原始file": file_orig,
            "原始line": line_orig,
            "repo_url": repo_url,
            "commit": commit,
            "匹配失败原因": fix_reason,
            "检索命中详情": json.dumps(hit_info, ensure_ascii=False)
        })
        return node_meta


def full_batch_pipeline(cmd_start=None, cmd_end=None, cmd_max=None):
    """
    读取规则优先级：命令行区间 > 命令行前N行 > config区间 > config前N行 > 全量
    """
    use_range = False
    use_max = False
    start = 0
    end = 0
    max_n = 0

    # 1. 解析命令行传入参数
    if cmd_start is not None and cmd_end is not None and cmd_start > 0 and cmd_end >= cmd_start:
        start, end = cmd_start, cmd_end
        use_range = True
    elif cmd_max is not None and cmd_max >= 0:
        max_n = cmd_max
        use_max = True
    else:
        # 2. 读取配置文件
        if READ_START_LINE > 0 and READ_END_LINE >= READ_START_LINE:
            start, end = READ_START_LINE, READ_END_LINE
            use_range = True
        else:
            max_n = READ_MAX_LINES
            use_max = True if max_n > 0 else False

    final_fix_lines = []
    human_csv_rows = []
    json_line_index = 1

    with open(ENTRIES_JSONL_FILE_PATH, "r", encoding="utf-8") as f_in:
        for raw_ln in f_in:
            # 区间模式：小于起始行跳过；超过结束行终止
            if use_range:
                if json_line_index < start:
                    json_line_index += 1
                    continue
                if json_line_index > end:
                    print(f"已读取到区间结束行{end}，终止读取")
                    break
            # 前N行模式：超出上限终止
            if use_max and json_line_index > max_n:
                print(f"已读取前{max_n}行上限，终止读取")
                break

            raw_ln = raw_ln.strip()
            if not raw_ln:
                json_line_index += 1
                continue
            try:
                line_data = json.loads(raw_ln)
            except json.JSONDecodeError:
                print(f"第{json_line_index}行JSON损坏，跳过")
                json_line_index += 1
                continue

            repo = line_data.get("repo_url", "")
            commit = line_data.get("commit", "")
            new_line_data = line_data.copy()

            entry_raw = line_data.get("entry_point", {})
            entry_meta = extract_info(entry_raw)
            new_entry = process_single_node(
                "entry_point", entry_meta, repo, commit, json_line_index, human_csv_rows
            )
            new_line_data["entry_point"] = new_entry

            crit_raw = line_data.get("critical_operation", {})
            crit_meta = extract_info(crit_raw)
            new_crit = process_single_node(
                "critical_operation", crit_meta, repo, commit, json_line_index, human_csv_rows
            )
            new_line_data["critical_operation"] = new_crit

            trace_new = []
            trace_list = line_data.get("trace", [])
            if isinstance(trace_list, list):
                for idx, trace_item in enumerate(trace_list):
                    trace_meta = extract_info(trace_item)
                    fixed_trace_item = process_single_node(
                        f"trace[{idx}]", trace_meta, repo, commit, json_line_index, human_csv_rows
                    )
                    trace_new.append(fixed_trace_item)
            new_line_data["trace"] = trace_new

            final_fix_lines.append(json.dumps(new_line_data, ensure_ascii=False))
            print(f"已处理JSONL第{json_line_index}行")
            json_line_index += 1

    # 写出文件
    with open(FIXED_JSONL_OUTPUT_PATH, "w", encoding="utf-8") as f_out:
        for line in final_fix_lines:
            f_out.write(line + "\n")

    if human_csv_rows:
        write_human_csv(NEEDS_HUMAN_CSV_PATH, human_csv_rows)
        print(f"人工待复核共{len(human_csv_rows)}条，写入{NEEDS_HUMAN_CSV_PATH}")

    if use_range:
        print(f"处理完成，本次读取区间：{start}~{end}，有效处理{len(final_fix_lines)}行")
    elif use_max:
        print(f"处理完成，本次读取前{max_n}行，有效处理{len(final_fix_lines)}行")
    else:
        print(f"处理完成，全文件读取完毕，有效处理{len(final_fix_lines)}行")
    print(f"修复文件输出路径：{FIXED_JSONL_OUTPUT_PATH}")


if __name__ == "__main__":
    # 命令行两种用法
    # 用法A：区间读取  python main.py 10 25  读取10~25行
    # 用法B：前N行读取 python main.py 8  读取前8行
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