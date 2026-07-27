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
    '''
    统一提取节点内file/line/code/desc字段，非字典直接返回全空字段
    node: 原始节点字典（entry_point/critical_operation/trace子项）
    return: 规整后的字典，固定包含file、line、code、desc四个key
    '''

    if not isinstance(node, dict):
        return {"file": None, "line": None, "code": None, "desc": None}
    return {
        "file": node.get("file", None),
        "line": node.get("line", None),
        "code": node.get("code", None),
        "desc": node.get("desc", None)
    }


def parse_line_range(raw_line_val):
    '''
    解析单行数字、区间字符串，转为起止行号；格式错误返回(None, None)
    raw_line_val: 原始line值，可以是int、纯数字字符串、横杠区间字符串
    return: (start_line, end_line)，单行则起止相同；解析失败则返回(None, None)
    '''

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
    '''
    文本归一化，用于代码比对；支持精准模式、宽松容错模式
    宽松模式：统一换行、首尾去空白、所有Tab/多空格压缩为单个空格
    精准模式：仅统一换行、清除首尾空白，保留行内空格Tab原样
    text: 待归一化的代码字符串
    loose_match: True宽松容错，False严格匹配
    return: 归一化完成的字符串
    '''

    if text is None:
        return ""
    unified = text.replace("\r\n", "\n").replace("\r", "\n")
    if loose_match:
        unified = re.sub(r"[\t ]+", " ", unified)
    return unified.strip()


def build_raw_link(repo_url: str, commit_hash: str, file_path: str) -> str:
    '''
    拼接GitHub raw文件直链，支持ghproxy镜像开关，规避github.com直接跳转raw.githubusercontent.com
    repo_url: 仓库主页地址
    commit_hash: 提交哈希值
    file_path: 仓库内文件路径
    :return: 可访问的raw完整URL，参数缺失返回空字符串
    '''

    if not repo_url or not commit_hash or not file_path:
        return ""
    repo_part = repo_url.replace("https://github.com/", "").strip("/")
    raw_link = f"https://raw.githubusercontent.com/{repo_part}/{commit_hash}/{file_path}"
    if USE_GHPROXY:
        raw_link = f"https://mirror.ghproxy.com/{raw_link}"
    return raw_link


def download_file(repo_url: str, commit: str, file_path: str):
    '''
    下载GitHub指定commit的文件，带全局缓存，避免重复请求；细化网络异常捕获
    repo_url: 仓库地址
    commit: commit哈希
    file_path: 文件路径
    return: (文件完整文本, 按行拆分列表, 错误信息)，无错则err为空字符串
    '''

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
    '''
    滑动窗口检索多行代码片段，宽松匹配，返回所有命中的起始自然行号（从1开始）
    file_lines: 文件所有行组成的列表
    target_loose: 已经宽松归一化后的目标代码
    return: 命中行号列表，无命中返回空列表
    '''

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
    '''
    调用GitHub API获取指定commit下所有文件路径，限制最大文件数量防止卡死
    repo_url: 仓库地址
    commit: commit哈希
    return: (文件路径列表, 错误信息)
    '''

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
    '''
    三级自动修复核心逻辑，优先级：±5行区间 → 当前全文件 → 全仓库
    仅宽松匹配唯一命中自动修改file/line；无命中/多命中/网络失败返回不可修复
    original_file: 原始文件路径
    original_line_raw: 原始行号/区间字符串
    repo_url: 仓库地址
    commit: commit哈希
    local_code: 需要匹配的代码片段
    return: (是否修复成功, 新file, 新line, 命中明细, 失败原因, 修复策略文案)
    '''
    
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

    # 总开关控制是否进入全仓库遍历（防卡死）
    if not ENABLE_WHOLE_REPO_SCAN:
        return False, original_file, original_line_raw, [], "已关闭全仓库检索，仅检索当前文件", ""

    # 提取原始文件后缀
    if "." in original_file:
        file_suffix = original_file.split(".")[-1]
    else:
        file_suffix = ""

    all_files, list_err = repo_list_all_files(repo_url, commit)
    if list_err:
        return False, original_file, original_line_raw, [], f"仓库文件列表获取失败：{list_err}", ""

    # 只保留后缀一致的文件
    same_suffix_files = []
    for path in all_files:
        if file_suffix == "":
            # 原始文件无后缀，匹配同样无后缀
            if "." not in path:
                same_suffix_files.append(path)
        else:
            if path.endswith(f".{file_suffix}"):
                same_suffix_files.append(path)

    repo_hits = []
    for fpath in same_suffix_files:
        f_cont, f_lines, f_err = download_file(repo_url, commit, fpath)
        if f_err:
            continue
        hits = search_code_in_file(f_lines, target_loose)
        for ln in hits:
            repo_hits.append({"file": fpath, "line": ln})

    if len(repo_hits) == 1:
        hit_item = repo_hits[0]
        return True, hit_item["file"], hit_item["line"], repo_hits, "", f"阶段3同后缀文件检索唯一命中，后缀.{file_suffix}，修正文件+行号"

    if len(repo_hits) == 0:
        return False, original_file, original_line_raw, [], f"本文件无命中，同后缀.{file_suffix}文件检索无匹配", ""
    else:
        return False, original_file, original_line_raw, repo_hits, f"命中{len(repo_hits)}处，多匹配无法自动修复", ""


def write_human_csv(csv_path, rows):
    '''
    写入人工复核CSV，自动判断是否需要写入表头，编码utf-8-sig
    csv_path: CSV文件路径
    rows: 字典列表，每一项是一行待写入数据
    return: 无返回值，直接落地文件
    '''

    header = [
        "entry_id", "节点字段路径", "原始file", "原始line", "原始desc",
        "repo_url", "commit", "无法修复原因", "命中明细"
    ]
    try:
        # w 模式：覆盖清空旧文件，重新创建
        with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=header)
            writer.writeheader()
            if rows:
                writer.writerows(rows)
    except Exception as e:
        print(f"needs_human.csv写入失败：{e}")


def write_fix_diff_csv(csv_path, rows):
    '''
    追加写入修改差异明细CSV，记录所有自动改动的新旧字段、修复方案
    csv_path: fix_diff.csv路径
    rows: 改动明细字典列表
    return: 无返回值，写入文件
    '''

    header = [
        "entry_id", "节点字段路径",
        "old_file", "old_line", "old_desc",
        "new_file", "new_line", "new_desc",
        "修复策略说明"
    ]
    try:
        # w 覆盖模式，每次运行清空历史
        with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=header)
            writer.writeheader()
            if rows:
                writer.writerows(rows)
    except Exception as e:
        print(f"fix_diff.csv写入失败：{e}")

def process_single_node(
    node_path: str, node_meta: dict, repo_url: str, commit: str, entry_id: str,
    human_list: list, diff_list: list
):
    '''
    处理单个代码节点（entry_point/critical_operation/trace项）：先校验匹配，失败则执行三级修复
    修复成功写入diff列表；无法修复写入人工列表；原本匹配直接返回原节点
    node_path: 节点路径标识，如entry_point、trace[0]
    node_meta: 节点原始字段字典
    repo_url: 当前行仓库地址
    commit: 当前行commit哈希
    entry_id: JSON自带entry_id字符串（entry-00057）
    human_list: 人工待复核列表，异常节点append到此
    diff_list: 修改明细列表，改动节点append到此
    return: 处理完成后的节点字典（可能修改file/line）
    '''
    file_orig = node_meta["file"]
    line_orig = node_meta["line"]
    code_local = node_meta["code"]
    desc_orig = node_meta["desc"]

    if not repo_url or not commit or not file_orig or code_local is None:
        human_list.append({
            "entry_id": entry_id,
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
        # 新旧完全一致，不记录diff
        if new_file == file_orig and new_line == line_orig:
            return node_meta

        # 判断代码是否多行：根据code是否包含换行符
        is_multi_line_code = "\n" in str(code_local)

        # 格式化旧行展示
        old_s, old_e = parse_line_range(line_orig)
        if is_multi_line_code:
            old_line_display = f"{old_s}-{old_e}"
        else:
            old_line_display = str(line_orig)

        # 格式化新行展示
        new_s, new_e = parse_line_range(new_line)
        if is_multi_line_code:
            new_line_display = f"{new_s}-{new_e}"
        else:
            new_line_display = str(new_line)

        diff_list.append({
            "entry_id": entry_id,
            "节点字段路径": node_path,
            "old_file": file_orig,
            "old_line": old_line_display,
            "old_desc": desc_orig,
            "new_file": new_file,
            "new_line": new_line_display,
            "new_desc": desc_orig,
            "修复策略说明": fix_strategy
        })
        return new_node
    else:
        human_list.append({
            "entry_id": entry_id,
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
    '''
    全流程入口主函数，统筹读取JSONL、按行处理所有节点、落地修复JSONL+两份CSV
    支持三种读取模式：区间行、前N行、全量；优先级：命令行参数 > config配置
    cmd_start: 命令行传入区间起始行，None代表不用命令行区间
    cmd_end: 命令行传入区间结束行
    cmd_max: 命令行传入前N行上限
    return: 无返回值，全部文件落地到配置路径
    '''

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
    file_row_index = 1  # 仅用于文件行数计数，不再当做业务entry_id

    with open(ENTRIES_JSONL_FILE_PATH, "r", encoding="utf-8") as f_in:
        for raw_ln in f_in:
            if use_range:
                if file_row_index < start:
                    file_row_index += 1
                    continue
                if file_row_index > end:
                    print(f"到达区间尾行{end}，终止读取")
                    break
            if use_max and file_row_index > max_n:
                print(f"到达前{max_n}行上限，终止读取")
                break

            raw_ln = raw_ln.strip()
            if not raw_ln:
                file_row_index += 1
                continue
            try:
                line_data = json.loads(raw_ln)
            except json.JSONDecodeError:
                print(f"文件物理行 {file_row_index} JSON格式损坏，跳过")
                file_row_index += 1
                continue

            # 从本条JSON读取原生entry_id，例如 entry-00057
            current_entry_id = line_data.get("entry_id", f"unknown-{file_row_index}")
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
                entry_id=current_entry_id,
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
                entry_id=current_entry_id,
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
                        entry_id=current_entry_id,
                        human_list=human_csv_rows,
                        diff_list=fix_diff_csv_rows
                    )
                    trace_new.append(fixed_trace_item)
            new_line_data["trace"] = trace_new

            final_fix_jsonl.append(json.dumps(new_line_data, ensure_ascii=False))
            print(f"完成文件物理行 {file_row_index}，本条entry_id：{current_entry_id} 校验处理")
            file_row_index += 1

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
    '''
    程序入口，解析命令行参数，区分区间/前N行两种入参，调用批量处理主函数
    命令行示例：python src\main.py 5 20 
    '''
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