#!/usr/bin/env python3
"""
节点修复引擎
包含核心修复逻辑 fix_node，以及处理整个分组（多个 entry）的函数。
"""

from pathlib import Path
from .config import LINE_RANGE, COMMON_EXTS
from .matcher import (
    normalize_code_lines,
    get_file_lines_local,
    find_matches_in_file_cached,
    search_in_repo_local,
    match_code_at          # 新增导入
)

def fix_node(node: dict,
             repo_path: Path,
             commit: str,
             file_cache: dict,
             match_cache: dict,
             repo_search_cache: dict):
    """
    修复单个节点的 file/line，按顺序尝试：
        1. 原始行 ±LINE_RANGE
        2. 全文件
        3. 全仓库（先原扩展名，再放宽到 COMMON_EXTS）

    Args:
        node (dict): 节点对象（含 file, line, code, desc 等）
        repo_path (Path): 已切换至目标 commit 的仓库路径
        commit (str): 当前 commit 哈希（用于缓存键，未直接使用）
        file_cache, match_cache, repo_search_cache: 本组内缓存的字典

    Returns:
        tuple: (new_node, strategy)
            - new_node: 修复后的节点，若无需修复则为 None
            - strategy: 描述字符串（如 '±5行唯一匹配'、'全文件多个匹配'）
    """
    file = node.get('file', '')
    line_raw = node.get('line', '')
    code = node.get('code', '')

    # ---------- 校验基本字段 ----------
    if not code or not file or not line_raw:
        return (node, '缺少必要字段')
    try:
        if isinstance(line_raw, str) and '-' in line_raw:
            line_num = int(line_raw.split('-')[0].strip())
        else:
            line_num = int(line_raw)
    except:
        line_num = 0
    if line_num <= 0:
        return (node, 'line无效')

    code_lines = normalize_code_lines(code)
    if not code_lines:
        return (node, 'code为空')

    file_path = repo_path / file

    # ---------- 步骤0：当前行匹配 ----------
    if file_path.exists():
        matches = find_matches_in_file_cached(file_path, code_lines, file_cache, match_cache)
        if line_num - 1 in matches:
            return (None, None)   # 无需修改

    # ---------- 步骤1：±5 行 ----------
    if file_path.exists():
        lines = get_file_lines_local(file_path, file_cache)
        if lines:
            start = max(0, line_num - 1 - LINE_RANGE)
            end = min(len(lines) - len(code_lines), line_num - 1 + LINE_RANGE)
            matches = []
            for i in range(start, end + 1):
                # 使用导入的 match_code_at
                if match_code_at(lines, i, code_lines):
                    matches.append(i)
            if len(matches) == 1:
                new_line = matches[0] + 1
                new_node = node.copy()
                new_node['line'] = new_line
                return (new_node, '±5行唯一匹配')
            elif len(matches) > 1:
                return (node, '±5行多个匹配')

    # ---------- 步骤2：全文件 ----------
    if file_path.exists():
        matches = find_matches_in_file_cached(file_path, code_lines, file_cache, match_cache)
        if len(matches) == 1:
            new_line = matches[0] + 1
            new_node = node.copy()
            new_node['line'] = new_line
            return (new_node, '全文件唯一匹配')
        elif len(matches) > 1:
            return (node, '全文件多个匹配')

    # ---------- 步骤3：全仓库 ----------
    ext = Path(file).suffix if file else ''
    ext_set = {ext} if ext else set()

    # 先只搜索原扩展名
    repo_result = search_in_repo_local(repo_path, code_lines, ext_set,
                                       file_cache, match_cache, repo_search_cache)
    if repo_result == 'MULTIPLE':
        return (node, '仓库多个匹配')
    if not repo_result:
        # 放宽到常见扩展名
        broad_exts = set(COMMON_EXTS)
        broad_exts.add(ext) if ext else None
        repo_result = search_in_repo_local(repo_path, code_lines, broad_exts,
                                           file_cache, match_cache, repo_search_cache)
        if repo_result == 'MULTIPLE':
            return (node, '仓库多个匹配')
        if not repo_result:
            return (node, '仓库未找到')

    # 唯一匹配
    total_matches = []
    for f, lines_list in repo_result.items():
        for l in lines_list:
            total_matches.append((f, l))
    if len(total_matches) == 1:
        new_file, new_line_idx = total_matches[0]
        new_line = new_line_idx + 1
        new_node = node.copy()
        new_node['file'] = new_file
        new_node['line'] = new_line
        return (new_node, '仓库唯一匹配')
    else:
        return (node, '仓库多个匹配')


def process_group(group_key: tuple, group_entries: list, prepare_repo_func):
    """
    处理一个 (repo_url, commit) 分组内的所有 entry。

    Args:
        group_key (tuple): (repo_url, commit)
        group_entries (list): [(idx, entry), ...]
        prepare_repo_func: 外部传入的仓库准备函数（用于解耦）

    Returns:
        tuple: (idx_entry_dict, diff_list, human_list, full_list)
            - idx_entry_dict: {idx: fixed_entry}
            - diff_list: fix_diff.csv 的记录列表
            - human_list: needs_human.csv 的记录列表
            - full_list: fix_full.csv 的记录列表
    """
    repo_url, commit = group_key

    # 准备仓库
    try:
        repo_path = prepare_repo_func(repo_url, commit)
    except Exception as e:
        # 如果 Git 失败，该组所有节点标记人工
        idx_entry_dict = {}
        diff_list = []
        human_list = []
        full_list = []
        for idx, entry in group_entries:
            entry_id = entry.get('entry_id', 'unknown')
            idx_entry_dict[idx] = entry
            for node_type in ['entry_point', 'critical_operation']:
                if node_type in entry:
                    node = entry[node_type]
                    reason = f'Git错误：{str(e)}'
                    human_list.append({'entry_id': entry_id, 'node_path': node_type, 'reason': reason})
                    full_list.append({
                        'entry_id': entry_id,
                        'node_path': node_type,
                        'original_file': node.get('file', ''),
                        'original_line': node.get('line', ''),
                        'original_desc': node.get('desc', ''),
                        'matched_file': node.get('file', ''),
                        'matched_line': node.get('line', ''),
                        'status': '人工复核',
                        'strategy': reason
                    })
            if 'trace' in entry:
                for i, node in enumerate(entry['trace']):
                    reason = f'Git错误：{str(e)}'
                    human_list.append({'entry_id': entry_id, 'node_path': f'trace[{i}]', 'reason': reason})
                    full_list.append({
                        'entry_id': entry_id,
                        'node_path': f'trace[{i}]',
                        'original_file': node.get('file', ''),
                        'original_line': node.get('line', ''),
                        'original_desc': node.get('desc', ''),
                        'matched_file': node.get('file', ''),
                        'matched_line': node.get('line', ''),
                        'status': '人工复核',
                        'strategy': reason
                    })
        return idx_entry_dict, diff_list, human_list, full_list

    # 初始化本组缓存
    file_cache = {}
    match_cache = {}
    repo_search_cache = {}

    idx_entry_dict = {}
    diff_list = []
    human_list = []
    full_list = []

    for idx, entry in group_entries:
        entry_id = entry.get('entry_id', 'unknown')
        new_entry = entry.copy()

        # ---------- 处理 entry_point ----------
        if 'entry_point' in new_entry:
            node = new_entry['entry_point']
            fixed_node, strategy = fix_node(node, repo_path, commit,
                                            file_cache, match_cache, repo_search_cache)
            if fixed_node is None:
                full_list.append({
                    'entry_id': entry_id,
                    'node_path': 'entry_point',
                    'original_file': node.get('file', ''),
                    'original_line': node.get('line', ''),
                    'original_desc': node.get('desc', ''),
                    'matched_file': node.get('file', ''),
                    'matched_line': node.get('line', ''),
                    'status': '无需修改',
                    'strategy': '当前行已匹配'
                })
            elif '多个' in strategy or '未找到' in strategy or '缺少' in strategy or '无效' in strategy:
                human_list.append({'entry_id': entry_id, 'node_path': 'entry_point', 'reason': strategy})
                full_list.append({
                    'entry_id': entry_id,
                    'node_path': 'entry_point',
                    'original_file': node.get('file', ''),
                    'original_line': node.get('line', ''),
                    'original_desc': node.get('desc', ''),
                    'matched_file': node.get('file', ''),
                    'matched_line': node.get('line', ''),
                    'status': '人工复核',
                    'strategy': strategy
                })
            else:
                new_entry['entry_point'] = fixed_node
                diff_list.append({
                    'entry_id': entry_id, 'node_path': 'entry_point',
                    'old_file': node.get('file', ''), 'old_line': node.get('line', ''),
                    'old_desc': node.get('desc', ''),
                    'new_file': fixed_node.get('file', ''), 'new_line': fixed_node.get('line', ''),
                    'new_desc': fixed_node.get('desc', ''),
                    'strategy': strategy
                })
                full_list.append({
                    'entry_id': entry_id,
                    'node_path': 'entry_point',
                    'original_file': node.get('file', ''),
                    'original_line': node.get('line', ''),
                    'original_desc': node.get('desc', ''),
                    'matched_file': fixed_node.get('file', ''),
                    'matched_line': fixed_node.get('line', ''),
                    'status': '自动修复',
                    'strategy': strategy
                })

        # ---------- 处理 critical_operation ----------
        if 'critical_operation' in new_entry:
            node = new_entry['critical_operation']
            fixed_node, strategy = fix_node(node, repo_path, commit,
                                            file_cache, match_cache, repo_search_cache)
            if fixed_node is None:
                full_list.append({
                    'entry_id': entry_id,
                    'node_path': 'critical_operation',
                    'original_file': node.get('file', ''),
                    'original_line': node.get('line', ''),
                    'original_desc': node.get('desc', ''),
                    'matched_file': node.get('file', ''),
                    'matched_line': node.get('line', ''),
                    'status': '无需修改',
                    'strategy': '当前行已匹配'
                })
            elif '多个' in strategy or '未找到' in strategy or '缺少' in strategy or '无效' in strategy:
                human_list.append({'entry_id': entry_id, 'node_path': 'critical_operation', 'reason': strategy})
                full_list.append({
                    'entry_id': entry_id,
                    'node_path': 'critical_operation',
                    'original_file': node.get('file', ''),
                    'original_line': node.get('line', ''),
                    'original_desc': node.get('desc', ''),
                    'matched_file': node.get('file', ''),
                    'matched_line': node.get('line', ''),
                    'status': '人工复核',
                    'strategy': strategy
                })
            else:
                new_entry['critical_operation'] = fixed_node
                diff_list.append({
                    'entry_id': entry_id, 'node_path': 'critical_operation',
                    'old_file': node.get('file', ''), 'old_line': node.get('line', ''),
                    'old_desc': node.get('desc', ''),
                    'new_file': fixed_node.get('file', ''), 'new_line': fixed_node.get('line', ''),
                    'new_desc': fixed_node.get('desc', ''),
                    'strategy': strategy
                })
                full_list.append({
                    'entry_id': entry_id,
                    'node_path': 'critical_operation',
                    'original_file': node.get('file', ''),
                    'original_line': node.get('line', ''),
                    'original_desc': node.get('desc', ''),
                    'matched_file': fixed_node.get('file', ''),
                    'matched_line': fixed_node.get('line', ''),
                    'status': '自动修复',
                    'strategy': strategy
                })

        # ---------- 处理 trace ----------
        if 'trace' in new_entry and isinstance(new_entry['trace'], list):
            new_trace = []
            for i, node in enumerate(new_entry['trace']):
                node_path = f'trace[{i}]'
                fixed_node, strategy = fix_node(node, repo_path, commit,
                                                file_cache, match_cache, repo_search_cache)
                if fixed_node is None:
                    new_trace.append(node)
                    full_list.append({
                        'entry_id': entry_id,
                        'node_path': node_path,
                        'original_file': node.get('file', ''),
                        'original_line': node.get('line', ''),
                        'original_desc': node.get('desc', ''),
                        'matched_file': node.get('file', ''),
                        'matched_line': node.get('line', ''),
                        'status': '无需修改',
                        'strategy': '当前行已匹配'
                    })
                elif '多个' in strategy or '未找到' in strategy or '缺少' in strategy or '无效' in strategy:
                    human_list.append({'entry_id': entry_id, 'node_path': node_path, 'reason': strategy})
                    new_trace.append(node)
                    full_list.append({
                        'entry_id': entry_id,
                        'node_path': node_path,
                        'original_file': node.get('file', ''),
                        'original_line': node.get('line', ''),
                        'original_desc': node.get('desc', ''),
                        'matched_file': node.get('file', ''),
                        'matched_line': node.get('line', ''),
                        'status': '人工复核',
                        'strategy': strategy
                    })
                else:
                    new_trace.append(fixed_node)
                    diff_list.append({
                        'entry_id': entry_id, 'node_path': node_path,
                        'old_file': node.get('file', ''), 'old_line': node.get('line', ''),
                        'old_desc': node.get('desc', ''),
                        'new_file': fixed_node.get('file', ''), 'new_line': fixed_node.get('line', ''),
                        'new_desc': fixed_node.get('desc', ''),
                        'strategy': strategy
                    })
                    full_list.append({
                        'entry_id': entry_id,
                        'node_path': node_path,
                        'original_file': node.get('file', ''),
                        'original_line': node.get('line', ''),
                        'original_desc': node.get('desc', ''),
                        'matched_file': fixed_node.get('file', ''),
                        'matched_line': fixed_node.get('line', ''),
                        'status': '自动修复',
                        'strategy': strategy
                    })
            new_entry['trace'] = new_trace

        idx_entry_dict[idx] = new_entry

    return idx_entry_dict, diff_list, human_list, full_list
