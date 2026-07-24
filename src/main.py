# src/main.py
from config import ENTRIES_JSONL_FILE_PATH


import json
import requests

# ===================== 全局配置（按需修改）=====================
# GITHUB_OWNER = "仓库拥有者用户名"
# GITHUB_REPO = "仓库名称"
# TARGET_COMMIT = "完整40位commit哈希字符串"  # 核心：固定commit，替代分支
USE_GHPROXY = True
TIMEOUT = 10
# ==========================================================


def extract_info(node: dict) -> dict:
    """
    通用提取函数：任意节点提取 {file, line, code, desc}
    字段不存在则填充 None
    """
    if not isinstance(node, dict):
        return {"file": None, "line": None, "code": None, "desc": None}
    return {
        "file": node.get("file", None),
        "line": node.get("line", None),
        "code": node.get("code", None),
        "desc": node.get("desc", None)
    }

def build_commit_raw_url(file_path: str) -> str:
    """拼接指定commit的raw链接，自动加国内加速"""
    if not file_path:
        return ""
    # commit替代分支，固定快照
    raw_link = f"https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}/raw/{TARGET_COMMIT}/{file_path}"
    if USE_GHPROXY:
        raw_link = f"https://mirror.ghproxy.com/{raw_link}"
    return raw_link
    
def parse_single_json_line(line_data: dict) -> dict:
    """
    处理单行完整JSON，分别提取三类节点信息
    :param line_data: json.loads得到的单行字典
    :return: 整理好的结构化数据
    """
    result = {}

    # 1. 处理 entry_point
    entry_node = line_data.get("entry_point", {})
    result["entry_point_info"] = extract_info(entry_node)

    # 2. 处理 critical_operation
    op_node = line_data.get("critical_operation", {})
    result["critical_op_info"] = extract_info(op_node)

    # 3. 遍历trace数组，逐个提取，存成列表
    trace_list = line_data.get("trace", [])
    trace_all_info = []
    for trace_item in trace_list:
        trace_all_info.append(extract_info(trace_item))
    result["trace_all_info"] = trace_all_info

    #拼接方式："repo_url"+/tree/+"commit"
    url_part_123 = line_data.get("repo_url", {})+"/raw/"+line_data.get("commit", {})

    # print(url_part_123)


    return result

def fetch_target_code_line(file_name: str, target_line: int) -> str:
    """
    根据file和line拉取github对应行代码
    :param file_name: JSON拿到的file路径
    :param target_line: JSON拿到的line行号（自然行号，从1开始）
    :return: 目标行文本 / 错误提示
    """
    if not file_name or target_line is None or not isinstance(target_line, int) or target_line < 1:
        return "无效文件路径或行号"

    url = url_part_123+file_name
    try:
        resp = requests.get(url, timeout=TIMEOUT)
        resp.raise_for_status()
        all_lines = resp.text.splitlines()
        idx = target_line - 1
        if 0 <= idx < len(all_lines):
            return all_lines[idx]
        else:
            return f"文件共{len(all_lines)}行，无第{target_line}行"
    except requests.exceptions.RequestException as e:
        return f"网络/访问失败：{str(e)}"


def read_all_jsonl_lines(file_path: str, only_first_line: bool = False):
    """
    主函数：逐行读取JSONL，自动解析每行所有节点信息
    """
    final_total = []  # 保存所有行解析结果
    with open(file_path, "r", encoding="utf-8") as f:
        line_idx = 1
        for raw_line in f:
            clean_line = raw_line.strip()
            if not clean_line:
                line_idx += 1
                continue
            try:
                row_json = json.loads(clean_line)
                # 核心处理：解析当前行全部节点
                row_parsed = parse_single_json_line(row_json)
                final_total.append(row_parsed)
                print(f"===== 第{line_idx}行解析完成 =====")
                # print(row_parsed)
            except json.JSONDecodeError:
                print(f"【报错】第{line_idx}行JSON非法，跳过")

            # 如果设置了只读首行，处理完当前行直接跳出循环
            if only_first_line:
                break

            line_idx += 1
    return final_total


# ===================== 调用示例 =====================
if __name__ == "__main__":
    all_result = read_all_jsonl_lines(ENTRIES_JSONL_FILE_PATH, only_first_line=True)
    # print(all_result)
    # all_result 是列表，每一项对应一行json的完整提取数据

