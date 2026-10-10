import re
import csv
import json
import shutil
import argparse
import subprocess
from pathlib import Path

# 路径常量
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
ENTRIES_PATH = PROJECT_ROOT / "data" / "entries.jsonl"
OUTPUT_DIR = PROJECT_ROOT / "reports"
CACHE_DIR = PROJECT_ROOT / ".cache" / "repos"

# 全仓库搜索时跳过的文件扩展名（图片、二进制、压缩包等）
SKIP_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.webp',
    '.ttf', '.woff', '.woff2', '.eot', '.otf',
    '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx',
    '.exe', '.dll', '.so', '.o', '.a', '.dylib',
    '.pyc', '.pyo', '.class', '.jar',
    '.mp3', '.mp4', '.avi', '.mov', '.wav',
    '.db', '.sqlite', '.sqlite3',
    '.lock', '.sum', '.mod',
    '.bin', '.dat', '.map',
}

# 超过此大小的文件跳过搜索，避免卡在大文件上
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB


# ============ 数据读取 ============

def load_entries(filepath):
    """读取entries.jsonl，每行一个JSON对象"""
    entries = []
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def group_entries(entries):
    """按(repo_url, commit)分组，方便集中处理同一个仓库的同一个版本"""
    groups = {}  # {(repo_url, commit): [entry1, entry2, ...]}
    for entry in entries:
        key = (entry["repo_url"], entry["commit"])
        groups.setdefault(key, []).append(entry)
    return groups


# ============ Git操作 ============

def get_or_clone_repo(repo_url):
    """检查仓库是否已缓存，不存在则clone"""
    parts = repo_url.rstrip('/').split('/')
    owner = parts[-2]
    repo = parts[-1]
    repo_dir = CACHE_DIR / owner / repo

    if not repo_dir.exists():
        repo_dir.parent.mkdir(parents=True, exist_ok=True)
        for i in range(3):
            try:
                subprocess.run(
                    ["git", "clone", repo_url, str(repo_dir)],
                    check=True, timeout=300,
                )
                break
            except subprocess.CalledProcessError:
                if repo_dir.exists():
                    shutil.rmtree(repo_dir)
                if i == 2:
                    raise
                print("  重试 clone...")

    return repo_dir


def checkout_commit(repo_dir, commit):
    """checkout到指定commit，失败则尝试fetch后再checkout"""
    try:
        subprocess.run(
            ["git", "-C", str(repo_dir), "checkout", "--quiet", commit],
            check=True, timeout=30,
            stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        try:
            subprocess.run(
                ["git", "-C", str(repo_dir), "fetch", "--quiet", "origin", commit],
                check=True, timeout=60,
                stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            )
            subprocess.run(
                ["git", "-C", str(repo_dir), "checkout", "--quiet", commit],
                check=True, timeout=30,
                stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            raise RuntimeError(f"commit {commit[:8]} 不存在或fetch超时")


# ============ 代码归一化 ============

def strip_cjk_comments(code):
    """去掉 // 或 # 后面含中文字符的注释，保留纯代码部分"""
    lines = code.split('\n')
    cleaned = []
    for line in lines:
        if '//' in line:
            after = line.split('//', 1)[1]
            if re.search(r'[\u4e00-\u9fff]', after):
                line = line.split('//', 1)[0]
        if '#' in line:
            after = line.split('#', 1)[1]
            if re.search(r'[\u4e00-\u9fff]', after):
                line = line.split('#', 1)[0]
        cleaned.append(line)
    return '\n'.join(cleaned)


def normalize_code(code, for_matching=False):
    """统一tab为4空格、去除行尾空白；for_matching时同时去掉中文注释"""
    if for_matching:
        code = strip_cjk_comments(code)
    lines = code.split('\n')
    normalized = []
    for line in lines:
        line = line.rstrip()
        line = line.replace('\t', '    ')
        normalized.append(line)
    return '\n'.join(normalized).strip()


def is_low_information(code):
    """判断代码片段是否太短（去空白后<10字符）或含省略号"""
    if not code or not code.strip():
        return True
    cleaned = strip_cjk_comments(code)
    cleaned = re.sub(r'\s+', '', cleaned)
    if len(cleaned) < 10:
        return True
    if '...' in code or '\u2026' in code:
        return True
    return False


# ============ 文件读取与代码搜索 ============

def read_file_lines(filepath):
    """读取文件所有行，失败或文件过大时返回None"""
    try:
        p = Path(filepath) if not isinstance(filepath, Path) else filepath
        if p.stat().st_size > MAX_FILE_SIZE:
            return None
        with open(p, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read().splitlines()
    except (FileNotFoundError, PermissionError, OSError):
        return None


def search_code_in_lines(lines, code, start_line=1, end_line=None):
    """在行列表中搜索代码，返回匹配的起始行号列表（1-based）"""
    if not lines:
        return []
    if end_line is None or end_line > len(lines):
        end_line = len(lines)

    start_idx = max(0, start_line - 1)
    # 搜索范围结尾扩展为 end_line + 代码行数 - 1，确保多行代码能被匹配到
    # 比如代码4行、line=100时，搜索范围是100~103而不是100~100
    normalized_search = normalize_code(code, for_matching=True)
    search_lines = normalized_search.split('\n')

    if len(search_lines) == 0:
        return []

    end_idx = min(len(lines), end_line + len(search_lines) - 1)

    matches = []
    for i in range(start_idx, max(start_idx, end_idx - len(search_lines) + 1)):
        candidate = '\n'.join(lines[i:i + len(search_lines)])
        if normalize_code(candidate, for_matching=True) == normalized_search:
            matches.append(i + 1)
    return matches


def search_code_in_range(filepath, code, start_line, end_line):
    """在文件指定行范围搜索"""
    lines = read_file_lines(filepath)
    if not lines:
        return []
    return search_code_in_lines(lines, code, start_line, end_line)


def search_code_in_file(filepath, code):
    """在整个文件搜索"""
    lines = read_file_lines(filepath)
    if not lines:
        return []
    return search_code_in_lines(lines, code, 1, len(lines))


def search_code_in_repo(repo_dir, code):
    """在全仓库搜索，返回[(relative_path, line), ...]"""
    matches = []
    for filepath in repo_dir.rglob('*'):
        if not filepath.is_file():
            continue
        if '.git' in filepath.parts:
            continue
        if filepath.suffix.lower() in SKIP_EXTENSIONS:
            continue
        try:
            file_matches = search_code_in_file(filepath, code)
            for line_num in file_matches:
                rel_path = filepath.relative_to(repo_dir)
                matches.append((str(rel_path), line_num))
        except Exception:
            continue
    return matches


# ============ 行号工具 ============

def normalize_line_value(line_val):
    """解析行号：int或"start-end"字符串，返回(start, end)或None"""
    if isinstance(line_val, int):
        if line_val < 1:
            return None
        return (line_val, line_val)
    elif isinstance(line_val, str):
        parts = line_val.split('-')
        if len(parts) == 2:
            try:
                a, b = int(parts[0]), int(parts[1])
                if a < 1 or b < a:
                    return None
                return (a, b)
            except ValueError:
                return None
    return None


def format_line_value(start, end, original_line):
    """格式化行号：单行返回int（如果原来是int），多行返回 start-end 字符串"""
    if start == end:
        if isinstance(original_line, int):
            return start
        return str(start)
    return f"{start}-{end}"


# ============ desc同步 ============

def sync_desc_location(desc, old_file, new_file, old_line, new_line):
    """
    当节点位置变化时，同步desc中引用的文件名和行号。
    只替换明确的引用（如"行 97"、"line 97"、文件basename），不碰步骤编号等。
    """
    if not desc:
        return desc

    updated = desc

    # 同步文件名（只替换basename，避免误伤）
    if old_file != new_file and old_file and new_file:
        old_name = Path(old_file).name
        new_name = Path(new_file).name
        if old_name != new_name and old_name in updated:
            updated = updated.replace(old_name, new_name)

    # 同步行号
    if old_line != new_line:
        old_str = str(old_line)
        new_str = str(new_line)
        # 中文行号引用
        for pattern in [f'\u7b2c{old_str}\u884c', f'\u884c{old_str}', f'\u884c {old_str}']:
            if pattern in updated:
                updated = updated.replace(pattern, pattern.replace(old_str, new_str))
                break
        # 英文行号引用
        for pattern in [f'line {old_str}', f'line{old_str}']:
            if pattern.lower() in updated.lower():
                updated = re.sub(re.escape(pattern), f'line {new_str}',
                                updated, flags=re.IGNORECASE)
                break

    return updated


# ============ 节点修复 ============

def fix_node(node, entry_id, node_name, repo_dir):
    """
    修复单个节点的file/line。
    搜索顺序：原位置 -> 原位置±5行 -> 原文件全文 -> 全仓库。
    只有唯一匹配才自动修复，多处命中或找不到则进入人工复核。
    返回: (fixed_node, fix_info, human_info, matched)
    """
    # 缺少code字段
    if not node or 'code' not in node:
        return node, None, {
            'entry_id': entry_id, 'node': node_name,
            'reason': 'missing_code',
            'file': node.get('file', '') if node else '',
            'line': str(node.get('line', '')) if node else '',
            'code': '',
        }, False

    code = node['code']
    original_file = node.get('file', '')
    original_line = node.get('line')
    original_desc = node.get('desc', '')

    # 行号无效（0、负数、格式错误）
    line_range = normalize_line_value(original_line)
    if line_range is None:
        return node, None, {
            'entry_id': entry_id, 'node': node_name,
            'reason': 'invalid_line',
            'file': original_file, 'line': str(original_line),
            'code': code[:100],
        }, False

    filepath = repo_dir / original_file

    # 步骤0：检查原始位置是否已经匹配
    if filepath.exists():
        matches = search_code_in_range(filepath, code, line_range[0], line_range[1])
        if matches:
            return node, None, None, True  # 原位匹配，无需修复

    # 步骤1：原始行号±5行范围搜索
    if filepath.exists():
        matches = search_code_in_range(
            filepath, code,
            max(1, line_range[0] - 5), line_range[1] + 5,
        )
        if len(matches) == 1:
            new_line = matches[0]
            code_lines = normalize_code(code).split('\n')
            new_end = new_line + len(code_lines) - 1
            fixed = node.copy()
            fixed['line'] = format_line_value(new_line, new_end, original_line)
            if original_desc:
                fixed['desc'] = sync_desc_location(
                    original_desc, original_file, original_file,
                    original_line, fixed['line'])
            return fixed, {
                'entry_id': entry_id, 'node': node_name,
                'old_file': original_file, 'old_line': str(original_line),
                'new_file': original_file, 'new_line': str(fixed['line']),
                'old_desc': original_desc, 'new_desc': fixed.get('desc', ''),
                'strategy': 'nearby_unique',
            }, None, False
        if len(matches) > 1:
            return node, None, {
                'entry_id': entry_id, 'node': node_name,
                'reason': 'multiple_matches',
                'file': original_file, 'line': str(original_line),
                'code': code[:100],
            }, False

    # 步骤2：原始文件全文搜索
    if filepath.exists():
        matches = search_code_in_file(filepath, code)
        if len(matches) == 1:
            new_line = matches[0]
            code_lines = normalize_code(code).split('\n')
            new_end = new_line + len(code_lines) - 1
            fixed = node.copy()
            fixed['line'] = format_line_value(new_line, new_end, original_line)
            if original_desc:
                fixed['desc'] = sync_desc_location(
                    original_desc, original_file, original_file,
                    original_line, fixed['line'])
            return fixed, {
                'entry_id': entry_id, 'node': node_name,
                'old_file': original_file, 'old_line': str(original_line),
                'new_file': original_file, 'new_line': str(fixed['line']),
                'old_desc': original_desc, 'new_desc': fixed.get('desc', ''),
                'strategy': 'same_file_unique',
            }, None, False
        if len(matches) > 1:
            return node, None, {
                'entry_id': entry_id, 'node': node_name,
                'reason': 'multiple_matches',
                'file': original_file, 'line': str(original_line),
                'code': code[:100],
            }, False

    # 步骤3：全仓库搜索
    repo_matches = search_code_in_repo(repo_dir, code)
    if len(repo_matches) == 1:
        new_file, new_line = repo_matches[0]
        code_lines = normalize_code(code).split('\n')
        new_end = new_line + len(code_lines) - 1
        fixed = node.copy()
        fixed['file'] = new_file
        fixed['line'] = format_line_value(new_line, new_end, original_line)
        if original_desc:
            fixed['desc'] = sync_desc_location(
                original_desc, original_file, new_file,
                original_line, fixed['line'])
        return fixed, {
            'entry_id': entry_id, 'node': node_name,
            'old_file': original_file, 'old_line': str(original_line),
            'new_file': new_file, 'new_line': str(fixed['line']),
            'old_desc': original_desc, 'new_desc': fixed.get('desc', ''),
            'strategy': 'repo_unique',
        }, None, False

    # 没找到或多处命中，进入人工复核
    if len(repo_matches) == 0:
        reason = 'low_information_not_found' if is_low_information(code) else 'code_not_found'
    else:
        reason = 'low_information_multiple' if is_low_information(code) else 'multiple_matches'

    return node, None, {
        'entry_id': entry_id, 'node': node_name,
        'reason': reason,
        'file': original_file, 'line': str(original_line),
        'code': code[:100],
    }, False


# ============ 批量处理 ============

def process_entries(repo_dir, entries_list, fix_diff_list, needs_human_list, stats):
    """处理一组共享同一repo+commit的entries"""
    for entry in entries_list:
        entry_id = entry['entry_id']

        # 处理 entry_point
        node = entry.get('entry_point')
        if node:
            fixed, fix_info, human_info, matched = fix_node(
                node, entry_id, 'entry_point', repo_dir)
            if fix_info:
                entry['entry_point'] = fixed
                fix_diff_list.append(fix_info)
                stats['fixed'] += 1
            elif human_info:
                needs_human_list.append(human_info)
                stats['human'] += 1
            elif matched:
                stats['matched'] += 1

        # 处理 critical_operation
        node = entry.get('critical_operation')
        if node:
            fixed, fix_info, human_info, matched = fix_node(
                node, entry_id, 'critical_operation', repo_dir)
            if fix_info:
                entry['critical_operation'] = fixed
                fix_diff_list.append(fix_info)
                stats['fixed'] += 1
            elif human_info:
                needs_human_list.append(human_info)
                stats['human'] += 1
            elif matched:
                stats['matched'] += 1

        # 处理 trace 节点
        trace = entry.get('trace', [])
        for i, trace_node in enumerate(trace):
            node_name = f'trace[{i}]'
            fixed, fix_info, human_info, matched = fix_node(
                trace_node, entry_id, node_name, repo_dir)
            if fix_info:
                trace[i] = fixed
                fix_diff_list.append(fix_info)
                stats['fixed'] += 1
            elif human_info:
                needs_human_list.append(human_info)
                stats['human'] += 1
            elif matched:
                stats['matched'] += 1


# ============ Schema校验 ============

def validate_output(entries):
    """检查输出是否满足SCHEMA.md基础约束"""
    errors = []
    for entry in entries:
        eid = entry.get('entry_id', 'unknown')

        # 必填字段
        for field in ['entry_id', 'report_id', 'repo_url', 'commit',
                       'entry_point', 'critical_operation', 'trace']:
            if field not in entry:
                errors.append(f"{eid}: 缺少 {field}")

        # commit格式（40位hex）
        commit = entry.get('commit', '')
        if not re.match(r'^[0-9a-f]{40}$', commit):
            errors.append(f"{eid}: commit格式错误")

        # entry_point 和 critical_operation
        for name in ['entry_point', 'critical_operation']:
            node = entry.get(name, {})
            for key in ['file', 'line', 'code']:
                if key not in node:
                    errors.append(f"{eid}: {name} 缺少 {key}")
            if normalize_line_value(node.get('line')) is None:
                errors.append(f"{eid}: {name} 行号无效 {node.get('line')}")

        # trace节点
        for i, t in enumerate(entry.get('trace', [])):
            for key in ['file', 'line', 'code']:
                if key not in t:
                    errors.append(f"{eid}: trace[{i}] 缺少 {key}")
            if normalize_line_value(t.get('line')) is None:
                errors.append(f"{eid}: trace[{i}] 行号无效 {t.get('line')}")

    return errors


# ============ 主函数 ============

def main():
    parser = argparse.ArgumentParser(description="VulnGym 代码定位修复")
    parser.add_argument('--input', default=str(ENTRIES_PATH), help='输入 JSONL 路径')
    args = parser.parse_args()

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print("VulnGym 代码定位修复")
    print("=" * 60)


    # 读取数据
    entries = load_entries(args.input)
    print(f"共 {len(entries)} 条 entries")

    # 分组
    groups = group_entries(entries)
    print(f"共 {len(groups)} 个仓库/commit组")

    fix_diff_list = []
    needs_human_list = []
    stats = {'fixed': 0, 'human': 0, 'matched': 0,
             'groups': 0, 'skipped': 0}

    # 逐组处理
    for idx, ((repo_url, commit), entries_list) in enumerate(
        sorted(groups.items(), key=lambda x: (x[0][0], x[0][1])), 1):
        repo_name = repo_url.split('/')[-1]

        # clone仓库
        try:
            repo_dir = get_or_clone_repo(repo_url)
        except Exception:
            print(f"[{idx}/{len(groups)}] clone失败: {repo_url}")
            stats['skipped'] += len(entries_list)
            for entry in entries_list:
                needs_human_list.append({
                    'entry_id': entry['entry_id'], 'node': 'ALL',
                    'reason': 'repo_unavailable',
                    'file': '', 'line': '', 'code': '',
                })
            continue

        print(f"[{idx}/{len(groups)}] {repo_name} @ {commit[:8]}")

        # checkout到对应commit
        try:
            checkout_commit(repo_dir, commit)
        except RuntimeError as e:
            print(f"  {e}")
            stats['skipped'] += len(entries_list)
            for entry in entries_list:
                needs_human_list.append({
                    'entry_id': entry['entry_id'], 'node': 'ALL',
                    'reason': f'commit_not_found: {commit[:8]}',
                    'file': '', 'line': '', 'code': '',
                })
            continue

        stats['groups'] += 1
        process_entries(repo_dir, entries_list, fix_diff_list,
                        needs_human_list, stats)

    # Schema校验
    schema_errors = validate_output(entries)

    # 排序输出（保证确定性）
    fix_diff_list.sort(key=lambda x: (x['entry_id'], x['node']))
    needs_human_list.sort(key=lambda x: (x['entry_id'], x['node']))

    # 写入 entries.fixed.jsonl
    output_path = PROJECT_ROOT / "data" / "entries.fixed.jsonl"
    with open(output_path, 'w', encoding='utf-8', newline='\n') as f:
        for entry in entries:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')

    # 写入 fix_diff.csv
    diff_path = OUTPUT_DIR / "fix_diff.csv"
    diff_fields = ['entry_id', 'node', 'old_file', 'old_line',
                   'new_file', 'new_line', 'old_desc', 'new_desc', 'strategy']
    with open(diff_path, 'w', encoding='utf-8', newline='\n') as f:
        writer = csv.DictWriter(f, fieldnames=diff_fields)
        writer.writeheader()
        writer.writerows(fix_diff_list)

    # 写入 needs_human.csv
    human_path = OUTPUT_DIR / "needs_human.csv"
    human_fields = ['entry_id', 'node', 'reason', 'file', 'line', 'code']
    with open(human_path, 'w', encoding='utf-8', newline='\n') as f:
        writer = csv.DictWriter(f, fieldnames=human_fields)
        writer.writeheader()
        writer.writerows(needs_human_list)

    # 打印摘要
    print("\n" + "=" * 60)
    print("修复完成！")
    print("=" * 60)
    print(f"总 entries: {len(entries)}")

    total_nodes = stats['fixed'] + stats['human'] + stats['matched']
    print(f"代码节点总数: {total_nodes}")
    print(f"原位匹配: {stats['matched']}")
    print(f"自动修复: {stats['fixed']}")
    strategy_counts = {}
    for fix in fix_diff_list:
        s = fix['strategy']
        strategy_counts[s] = strategy_counts.get(s, 0) + 1
    for s, c in sorted(strategy_counts.items()):
        print(f"  - {s}: {c}")
    print(f"人工复核: {stats['human']}")
    reason_counts = {}
    for item in needs_human_list:
        r = item['reason']
        reason_counts[r] = reason_counts.get(r, 0) + 1
    for r, c in sorted(reason_counts.items()):
        print(f"  - {r}: {c}")
    print(f"Schema错误: {len(schema_errors)}")
    print(f"处理组数: {stats['groups']}/{len(groups)}")
    print(f"跳过组数: {stats['skipped']}")

    print(f"\n输出文件:")
    print(f"  {output_path}")
    print(f"  {diff_path}")
    print(f"  {human_path}")


if __name__ == "__main__":
    main()
