#!/usr/bin/env python3
"""
VulnGym 入口位置自动修复脚本 - 主入口

此脚本协调各模块完成以下任务：
    1. 读取 data/entries.jsonl
    2. 按 (repo_url, commit) 分组
    3. 并行处理每个分组（8 线程）
    4. 输出修复后的 JSONL 及多种审计 CSV

用法：
    python tools/fix_entry_locations.py
"""

import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from fix_lib.config import (
    DATA_FILE, OUTPUT_DIR,
    OUTPUT_JSONL, OUTPUT_DIFF, OUTPUT_HUMAN, OUTPUT_FULL,
    MAX_WORKERS
)
from fix_lib.io_utils import read_entries, write_jsonl, write_csv
from fix_lib.git_utils import prepare_repo
from fix_lib.fixer import process_group

def main():
    start_time = time.time()
    print("📖 正在读取 data/entries.jsonl ...")
    entries = read_entries(DATA_FILE)
    total_entries = len(entries)
    print(f"✅ 共读取 {total_entries} 条 Entry\n")

    # ---------- 分组 ----------
    groups = defaultdict(list)
    for idx, entry in enumerate(entries):
        key = (entry.get('repo_url', ''), entry.get('commit', ''))
        groups[key].append((idx, entry))

    total_groups = len(groups)
    print(f"📦 共分为 {total_groups} 个 (repo, commit) 分组")
    print(f"🚀 使用 {MAX_WORKERS} 个线程并行处理\n")

    # ---------- 分离特殊分组（缺少 repo_url/commit） ----------
    normal_groups = []
    special_groups = []
    for key, group_entries in groups.items():
        repo_url, commit = key
        if not repo_url or not commit:
            special_groups.append((key, group_entries))
        else:
            normal_groups.append((key, group_entries))

    # ---------- 容器 ----------
    fixed_entries_dict = {}
    all_diff = []
    all_human = []
    all_full = []

    # 特殊分组直接人工
    for key, group_entries in special_groups:
        for idx, entry in group_entries:
            entry_id = entry.get('entry_id', 'unknown')
            fixed_entries_dict[idx] = entry
            for node_type in ['entry_point', 'critical_operation']:
                if node_type in entry:
                    node = entry[node_type]
                    reason = '缺少 repo_url 或 commit'
                    all_human.append({'entry_id': entry_id, 'node_path': node_type, 'reason': reason})
                    all_full.append({
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
                    reason = '缺少 repo_url 或 commit'
                    all_human.append({'entry_id': entry_id, 'node_path': f'trace[{i}]', 'reason': reason})
                    all_full.append({
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

    # ---------- 并行处理正常分组 ----------
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_group = {}
        for key, group_entries in normal_groups:
            # 传入 prepare_repo 函数供 process_group 使用
            future = executor.submit(process_group, key, group_entries, prepare_repo)
            future_to_group[future] = (key, group_entries)

        processed_groups = 0
        for future in as_completed(future_to_group):
            key, group_entries = future_to_group[future]
            try:
                idx_entry_dict, diff_list, human_list, full_list = future.result()
                fixed_entries_dict.update(idx_entry_dict)
                all_diff.extend(diff_list)
                all_human.extend(human_list)
                all_full.extend(full_list)
                processed_groups += 1
                sys.stdout.write(f"\r📊 已完成分组: {processed_groups}/{len(normal_groups)}")
                sys.stdout.flush()
            except Exception as e:
                print(f"\n❌ 分组处理失败: {key} - {e}")
                # 该组所有 entry 原样保留，标记人工
                for idx, entry in group_entries:
                    entry_id = entry.get('entry_id', 'unknown')
                    fixed_entries_dict[idx] = entry
                    for node_type in ['entry_point', 'critical_operation']:
                        if node_type in entry:
                            node = entry[node_type]
                            reason = f'处理异常：{str(e)}'
                            all_human.append({'entry_id': entry_id, 'node_path': node_type, 'reason': reason})
                            all_full.append({
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
                            reason = f'处理异常：{str(e)}'
                            all_human.append({'entry_id': entry_id, 'node_path': f'trace[{i}]', 'reason': reason})
                            all_full.append({
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
                processed_groups += 1
                sys.stdout.write(f"\r📊 已完成分组: {processed_groups}/{len(normal_groups)}")
                sys.stdout.flush()

    print("\n")

    # ---------- 构建最终列表 ----------
    fixed_entries = [None] * total_entries
    for idx, entry in fixed_entries_dict.items():
        fixed_entries[idx] = entry

    # ---------- 统计 ----------
    total_nodes = 0
    for entry in fixed_entries:
        if entry is None:
            continue
        if 'entry_point' in entry:
            total_nodes += 1
        if 'critical_operation' in entry:
            total_nodes += 1
        if 'trace' in entry:
            total_nodes += len(entry['trace'])

    human_nodes = len(all_human)
    fixed_count = len(all_diff)

    print("📊 统计信息：")
    print(f"   总节点数: {total_nodes}")
    print(f"   自动修复: {fixed_count} 个节点")
    print(f"   需人工复核: {human_nodes} 个节点")
    print(f"   无需修改: {total_nodes - fixed_count - human_nodes} 个节点")

    # ---------- 创建输出目录 ----------
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # ---------- 写入输出 ----------
    print("\n💾 正在写入输出文件...")
    write_jsonl(OUTPUT_JSONL, fixed_entries)
    print(f"   ✅ {OUTPUT_JSONL}")

    if all_diff:
        write_csv(OUTPUT_DIFF,
                  ['entry_id', 'node_path', 'old_file', 'old_line', 'old_desc',
                   'new_file', 'new_line', 'new_desc', 'strategy'],
                  all_diff)
        print(f"   ✅ {OUTPUT_DIFF} ({fixed_count} 处修改)")
    else:
        print(f"   ⚠️  {OUTPUT_DIFF} 无修改记录，未生成")

    if all_human:
        write_csv(OUTPUT_HUMAN,
                  ['entry_id', 'node_path', 'reason'],
                  all_human)
        print(f"   ✅ {OUTPUT_HUMAN} ({human_nodes} 个节点需人工复核)")
    else:
        print(f"   ✅ {OUTPUT_HUMAN} 无需人工复核，未生成")

    if all_full:
        write_csv(OUTPUT_FULL,
                  ['entry_id', 'node_path', 'original_file', 'original_line', 'original_desc',
                   'matched_file', 'matched_line', 'status', 'strategy'],
                  all_full)
        print(f"   ✅ {OUTPUT_FULL} ({len(all_full)} 条详细记录)")
    else:
        print(f"   ⚠️  {OUTPUT_FULL} 无记录，未生成")

    elapsed = time.time() - start_time
    print(f"\n⏱️  总运行时间: {elapsed:.2f} 秒")
    print("🎉 全部完成！")

if __name__ == '__main__':
    main()
