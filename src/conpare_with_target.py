from config import ENTRIES_JSONL_FILE_PATH

import json
import requests
import urllib3
import re
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

USE_GHPROXY = False
TIMEOUT = 25  # 拉长超时时间
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
}


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


def build_dynamic_raw_url(repo_url: str, commit_hash: str, file_path: str) -> str:
    # 拆分repo地址：https://github.com/用户名/仓库名
    if not repo_url or not commit_hash or not file_path:
        return ""
    # 提取owner/repo
    repo_part = repo_url.replace("https://github.com/", "").strip("/")
    # 直连raw.githubusercontent，无跳转
    raw_link = f"https://raw.githubusercontent.com/{repo_part}/{commit_hash}/{file_path}"
    return raw_link


def verify_node_code(node_info: dict, repo_url: str, commit_hash: str) -> dict:
    file = node_info["file"]
    raw_line = node_info["line"]
    local_code = node_info["code"]

    verify_result = {
        "match": False,
        "reason": ""
    }

    if not repo_url:
        verify_result["reason"] = "repo_url为空"
        verify_result["check_url"] = build_dynamic_raw_url(repo_url, commit_hash, file)
        return verify_result
    if not commit_hash:
        verify_result["reason"] = "commit为空"
        verify_result["check_url"] = build_dynamic_raw_url(repo_url, commit_hash, file)
        return verify_result
    if not file:
        verify_result["reason"] = "file为空"
        verify_result["check_url"] = build_dynamic_raw_url(repo_url, commit_hash, file)
        return verify_result

    start_line, end_line = parse_line_range(raw_line)
    if start_line is None or start_line < 1 or end_line < 1:
        verify_result["reason"] = f"行号格式无效，原始line值：{raw_line}"
        verify_result["check_url"] = build_dynamic_raw_url(repo_url, commit_hash, file)
        return verify_result

    if local_code is None:
        verify_result["reason"] = "code为空无法比对"
        verify_result["check_url"] = build_dynamic_raw_url(repo_url, commit_hash, file)
        return verify_result

    url = build_dynamic_raw_url(repo_url, commit_hash, file)
    try:
        resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False)
        resp.raise_for_status()
        file_lines = resp.text.splitlines()
        total_lines = len(file_lines)

        start_idx = start_line - 1
        end_idx = end_line - 1
        if start_idx < 0 or end_idx >= total_lines:
            verify_result["reason"] = f"行号越界。解析区间{start_line}-{end_line}，文件总行数{total_lines}"
            verify_result["check_url"] = url
            return verify_result

        online_raw_code = "\n".join(file_lines[start_idx: end_idx + 1])
        local_raw_code = local_code

        local_strict = normalize_text(local_raw_code, loose_match=False)
        online_strict = normalize_text(online_raw_code, loose_match=False)
        local_loose = normalize_text(local_raw_code, loose_match=True)
        online_loose = normalize_text(online_raw_code, loose_match=True)

        if online_strict == local_strict:
            verify_result["match"] = True
            verify_result["reason"] = "精准匹配成功（换行/首尾空白一致）"
        elif online_loose == local_loose:
            verify_result["match"] = True
            verify_result["reason"] = "容错匹配成功（忽略空格/Tab/首尾空白差异）"
        else:
            verify_result["reason"] = "代码内容不匹配（精准、宽松两种模式均不一致）"
            verify_result["check_url"] = url
            verify_result["online_raw_code"] = online_raw_code
            verify_result["local_raw_code"] = local_raw_code
            verify_result["online_normalized_strict"] = online_strict
            verify_result["local_normalized_strict"] = local_strict
            verify_result["online_normalized_loose"] = online_loose
            verify_result["local_normalized_loose"] = local_loose

    except requests.exceptions.RequestException as e:
        error_detail = str(e)
        verify_result["reason"] = f"访问失败，原始报错：{error_detail}"
        verify_result["check_url"] = url
    return verify_result


def parse_and_verify_line(line_data: dict) -> dict:
    repo_url = line_data.get("repo_url", "")
    commit_hash = line_data.get("commit", "")

    final = {}

    entry_raw = line_data.get("entry_point", {})
    entry_meta = extract_info(entry_raw)
    final["entry_point"] = verify_node_code(entry_meta, repo_url, commit_hash)

    op_raw = line_data.get("critical_operation", {})
    op_meta = extract_info(op_raw)
    final["critical_operation"] = verify_node_code(op_meta, repo_url, commit_hash)

    trace_raw = line_data.get("trace", [])
    trace_check_list = []
    if isinstance(trace_raw, list):
        for item in trace_raw:
            trace_meta = extract_info(item)
            trace_check_list.append(verify_node_code(trace_meta, repo_url, commit_hash))
    final["trace"] = trace_check_list
    final["repo_commit"] = {"repo_url": repo_url, "commit": commit_hash}
    return final


def jsonl_batch_check(file_path: str, only_first_line: bool = False):
    all_results = []
    with open(file_path, "r", encoding="utf-8") as f:
        line_no = 1
        for raw_line in f:
            clean_line = raw_line.strip()
            if not clean_line:
                line_no += 1
                continue
            try:
                json_obj = json.loads(clean_line)
                line_result = parse_and_verify_line(json_obj)
                all_results.append({
                    "json行号": line_no,
                    "校验结果": line_result
                })
                print(f"JSONL第{line_no}行校验完毕")
            except json.JSONDecodeError:
                print(f"第{line_no}行JSON损坏，跳过")

            if only_first_line:
                break
            line_no += 1
    return all_results


if __name__ == "__main__":
    res = jsonl_batch_check(ENTRIES_JSONL_FILE_PATH, only_first_line=True)
    print(json.dumps(res, ensure_ascii=False, indent=2))