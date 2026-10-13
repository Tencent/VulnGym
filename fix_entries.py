#!/usr/bin/env python3
"""
VulnGym Issue #4 — 修复 entries.jsonl 中代码片段定位偏差

修复顺序：
  0. 原位验证
  1. 原行号 ±5 行范围搜索
  2. 原文件全文搜索
  3. 整个仓库搜索（唯一命中时同时修正 file + line）
  4. 无法确定 → needs_human.csv，不做自动修改

实现说明：
- 单文件内容通过 GitHub Raw API 获取，并做内存缓存
- 全仓库搜索通过 GitHub tarball 下载指定 commit 快照，并做本地缓存
- 保守策略：只在唯一命中时自动修改；多命中/找不到一律进入人工复核
"""

import argparse
import csv
import io
import json
import os
import shutil
import sys
import tarfile
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

SEARCH_RANGE = 5
REQUEST_TIMEOUT = 20
MAX_RETRIES = 2
DEFAULT_WORKERS = 6
TEXT_FILE_EXTENSIONS = {
    '.c', '.cc', '.cpp', '.cxx', '.h', '.hpp', '.hh',
    '.go', '.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.kt', '.rs',
    '.php', '.rb', '.swift', '.scala', '.cs', '.m', '.mm', '.sql',
    '.sh', '.bash', '.zsh', '.ps1', '.yaml', '.yml', '.json', '.toml',
    '.ini', '.cfg', '.conf', '.md', '.txt', '.xml', '.html', '.htm',
    '.css', '.scss', '.less', '.vue', '.svelte', '.dockerfile', '.gradle'
}
IGNORE_DIRS = {
    '.git', 'node_modules', '__pycache__', '.next', '.nuxt', 'dist', 'build',
    'coverage', 'vendor', 'target', '.venv', 'venv', '.idea', '.vscode'
}
MAX_FILE_SIZE = 2 * 1024 * 1024

_file_cache: dict[tuple, list[str] | None] = {}
_repo_cache: dict[tuple, Path | None] = {}
_repo_cache_lock = threading.Lock()


def normalize_code(code: str) -> str:
    text = code.replace('\t', '    ')
    lines = text.split('\n')
    cleaned = []
    prev_empty = False
    for line in lines:
        stripped = line.strip()
        if stripped == '':
            if not prev_empty:
                cleaned.append('')
                prev_empty = True
        else:
            cleaned.append(stripped)
            prev_empty = False
    return '\n'.join(cleaned).strip()


# 这些字符串只会匹配代码块的闭合符号，不包含有意义逻辑
_DEGENERATE_STRINGS = {
    '}', '});', '};', '];', ')];',
    ')', ']', '{', '});', ')};',
    '});', ');', '}]);', '}));',
    '', ' ', '  ', '\t',
}


def is_degenerate_snippet(code: str) -> bool:
    """检测是否是无意义的退化代码片段（单独的闭合括号等）。"""
    stripped = code.strip()
    if stripped in _DEGENERATE_STRINGS:
        return True
    if len(stripped) <= 2 and all(c in '{}[]();,' for c in stripped):
        return True
    return False


def search_code_in_lines(lines: list[str], norm_code: str) -> list[int]:
    code_lines = norm_code.split('\n')
    if not code_lines or not lines:
        return []

    results = []
    window_size = len(code_lines)
    for i in range(len(lines) - window_size + 1):
        window = ''.join(lines[i:i + window_size])
        if normalize_code(window) == norm_code:
            results.append(i + 1)
    return results


def _parse_line(line_value):
    if isinstance(line_value, int):
        return line_value, line_value
    if isinstance(line_value, str) and '-' in line_value:
        parts = line_value.split('-', 1)
        try:
            return int(parts[0]), int(parts[1])
        except (ValueError, IndexError):
            return None, None
    try:
        n = int(line_value)
        return n, n
    except (ValueError, TypeError):
        return None, None


# ─── desc 字段行号同步 ───────────────────────
# 匹配中文描述中的 "第 N 行" / "行号为 N" / "line:N" 等模式
import re as _re

_DESC_LINE_PATTERNS = [
    _re.compile(r'(\D)(\d{1,5})(\s*[-–—至到]\s*)(\d{1,5})(\s*行)'),           # "第 100-105 行"
    _re.compile(r'(\D)(\d{1,5})(\s*[-–—至到]\s*)(\d{1,5})\b'),                  # "100-105" (bare)
    _re.compile(r'(?:line|行号为?|第)\s*(\d{1,5})\b', _re.IGNORECASE),           # "line 100" / "第100行"
    _re.compile(r'(?:L)\s*(\d{1,5})\b'),                                          # "L100"
]


def sync_desc(desc: str, old_file: str, new_file: str,
              old_line_start: int, old_line_end: int,
              new_line_start: int, new_line_end: int | None = None) -> str:
    """保守同步 desc 中的行号引用。

    只在 file 不变时更新行号引用；file 变化时不做行号替换。
    """
    if old_file != new_file:
        return desc
    if new_line_end is None:
        new_line_end = new_line_start

    old_line_diff = old_line_end - old_line_start
    new_line_diff = new_line_end - new_line_start

    # 先处理范围格式: "100-105行" / "lines 100-105"
    for pattern in _DESC_LINE_PATTERNS[:2]:
        def _replace_range(m):
            a, b = int(m.group(2)), int(m.group(4))
            if a <= old_line_start <= b:
                ra = new_line_start
                rb = new_line_start + (b - a)
                sep = m.group(3)
                suffix = m.group(5) if len(m.groups()) >= 5 else ''
                return f'{m.group(1)}{ra}{sep}{rb}{suffix}'
            return m.group(0)
        desc = pattern.sub(_replace_range, desc)

    # 再处理单行格式: "line 100" / "第100行" / "L100"
    for pattern in _DESC_LINE_PATTERNS[2:]:
        def _replace_single(m):
            n = int(m.group(1))
            if n == old_line_start or old_line_start <= n <= old_line_end:
                delta = n - old_line_start
                return m.group(0).replace(str(n), str(new_line_start + delta))
            return m.group(0)
        desc = pattern.sub(_replace_single, desc)

    return desc


def build_raw_url(repo_url: str, commit: str, filepath: str) -> str:
    owner_repo = repo_url.replace('https://github.com/', '').rstrip('/').removesuffix('.git')
    return f'https://raw.githubusercontent.com/{owner_repo}/{commit}/{filepath}'


def build_tarball_url(repo_url: str, commit: str) -> str:
    owner_repo = repo_url.replace('https://github.com/', '').rstrip('/').removesuffix('.git')
    return f'https://codeload.github.com/{owner_repo}/tar.gz/{commit}'


def fetch_file_lines(repo_url: str, commit: str, filepath: str) -> list[str] | None:
    cache_key = (repo_url, commit, filepath)
    if cache_key in _file_cache:
        return _file_cache[cache_key]

    url = build_raw_url(repo_url, commit, filepath)
    for attempt in range(MAX_RETRIES + 1):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'VulnGym-Fixer/1.0'})
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                raw = resp.read().decode('utf-8', errors='replace')
                result = raw.splitlines(keepends=True)
                _file_cache[cache_key] = result
                return result
        except urllib.error.HTTPError as e:
            if e.code == 404:
                _file_cache[cache_key] = None
                return None
            if attempt < MAX_RETRIES:
                time.sleep(1)
        except Exception:
            if attempt < MAX_RETRIES:
                time.sleep(2)
    _file_cache[cache_key] = None
    return None


def fetch_repo_snapshot(repo_url: str, commit: str, repo_cache_dir: Path) -> Path | None:
    cache_key = (repo_url, commit)
    with _repo_cache_lock:
        if cache_key in _repo_cache:
            return _repo_cache[cache_key]

    owner_repo = repo_url.replace('https://github.com/', '').rstrip('/').removesuffix('.git')
    repo_dir = repo_cache_dir / owner_repo.replace('/', '__') / commit
    ready_marker = repo_dir / '.ready'
    if ready_marker.exists():
        with _repo_cache_lock:
            _repo_cache[cache_key] = repo_dir
        return repo_dir

    repo_dir.parent.mkdir(parents=True, exist_ok=True)
    if repo_dir.exists():
        shutil.rmtree(repo_dir, ignore_errors=True)
    repo_dir.mkdir(parents=True, exist_ok=True)

    url = build_tarball_url(repo_url, commit)
    for attempt in range(MAX_RETRIES + 1):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'VulnGym-Fixer/1.0'})
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT * 2) as resp:
                archive_bytes = resp.read()

            with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode='r:gz') as tar:
                tar.extractall(repo_dir)

            children = [p for p in repo_dir.iterdir() if p.is_dir()]
            if len(children) == 1:
                extracted_root = children[0]
                for child in extracted_root.iterdir():
                    shutil.move(str(child), str(repo_dir / child.name))
                extracted_root.rmdir()

            ready_marker.write_text('ok', encoding='utf-8')
            with _repo_cache_lock:
                _repo_cache[cache_key] = repo_dir
            return repo_dir
        except urllib.error.HTTPError as e:
            if e.code == 404:
                break
            if attempt < MAX_RETRIES:
                time.sleep(1)
        except Exception:
            if attempt < MAX_RETRIES:
                time.sleep(2)

    shutil.rmtree(repo_dir, ignore_errors=True)
    with _repo_cache_lock:
        _repo_cache[cache_key] = None
    return None


def should_scan_file(file_path: Path) -> bool:
    if file_path.suffix.lower() in TEXT_FILE_EXTENSIONS:
        return True
    name = file_path.name.lower()
    if name == 'dockerfile' or name.endswith('.dockerfile'):
        return True
    return False


def search_code_in_repo(repo_dir: Path, norm_code: str, current_file: str) -> tuple[str, int] | None | str:
    matches: list[tuple[str, int]] = []
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        for filename in files:
            file_path = Path(root) / filename
            if file_path.name == '.ready' or not should_scan_file(file_path):
                continue
            try:
                if file_path.stat().st_size > MAX_FILE_SIZE:
                    continue
            except OSError:
                continue

            try:
                text = file_path.read_text(encoding='utf-8', errors='replace')
            except Exception:
                continue

            lines = text.splitlines(keepends=True)
            found = search_code_in_lines(lines, norm_code)
            for line_no in found:
                rel_path = file_path.relative_to(repo_dir).as_posix()
                matches.append((rel_path, line_no))
                if len(matches) > 1:
                    return 'multi_hit'

    if len(matches) == 1:
        return matches[0]
    return None


def verify_node(repo_url: str, commit: str, node: dict, repo_cache_dir: Path) -> dict:
    code = node.get('code', '')
    filepath = node.get('file', '')
    raw_line = node.get('line')

    if not code or not filepath:
        return {'strategy': 'correct', 'new_node': node, 'reason': 'empty code/file'}

    line_start, line_end = _parse_line(raw_line)
    if line_start is None:
        return {'strategy': 'correct', 'new_node': node, 'reason': f'invalid line: {raw_line}'}

    lines = fetch_file_lines(repo_url, commit, filepath)
    if lines is None:
        # 先不立刻放弃，后面会尝试仓库级搜索
        lines = []

    norm_code = normalize_code(code)
    if not norm_code:
        return {'strategy': 'correct', 'new_node': node, 'reason': 'empty code after normalize'}

    # 退化片段检测：单独的 `}` / `)` 等闭合符号不自动修复
    if is_degenerate_snippet(norm_code):
        return {'strategy': 'degenerate', 'new_node': node,
                'reason': f'degenerate snippet (auto-fix skipped): {repr(code.strip()[:60])}'}

    code_line_count = len(norm_code.split('\n'))
    effective_end = max(line_end, line_start + code_line_count - 1)

    if lines:
        current_code = ''.join(lines[max(0, line_start - 1):min(len(lines), effective_end)])
        if normalize_code(current_code) == norm_code:
            if effective_end != line_end and isinstance(raw_line, int):
                new_node = dict(node)
                new_node['line'] = f'{line_start}-{effective_end}'
                if 'desc' in node and isinstance(node['desc'], str) and node['desc']:
                    new_node['desc'] = sync_desc(
                        node['desc'], filepath, filepath,
                        line_start, line_end, line_start, effective_end)
                return {
                    'strategy': 'nearby_fix',
                    'new_node': new_node,
                    'reason': f'expanded line {raw_line} -> {line_start}-{effective_end} (code spans {code_line_count} lines)'
                }
            return {'strategy': 'correct', 'new_node': node, 'reason': 'already correct'}

        search_start = max(0, line_start - 1 - SEARCH_RANGE)
        search_end = min(len(lines), effective_end + SEARCH_RANGE)
        nearby = lines[search_start:search_end]
        if nearby:
            matches = search_code_in_lines(nearby, norm_code)
            if len(matches) == 1:
                new_line = search_start + matches[0]
                new_node = dict(node)
                new_node['line'] = new_line
                if 'desc' in node and isinstance(node['desc'], str) and node['desc']:
                    new_node['desc'] = sync_desc(
                        node['desc'], filepath, filepath,
                        line_start, line_end, new_line, new_line)
                return {
                    'strategy': 'nearby_fix',
                    'new_node': new_node,
                    'reason': f'line {raw_line} -> {new_line} (within +/-{SEARCH_RANGE})'
                }
            if len(matches) > 1:
                return {'strategy': 'multi_hit', 'new_node': node, 'reason': f'{len(matches)} matches nearby line {raw_line}'}

        matches = search_code_in_lines(lines, norm_code)
        if len(matches) == 1:
            new_node = dict(node)
            new_node['line'] = matches[0]
            if 'desc' in node and isinstance(node['desc'], str) and node['desc']:
                new_node['desc'] = sync_desc(
                    node['desc'], filepath, filepath,
                    line_start, line_end, matches[0], matches[0])
            return {
                'strategy': 'file_search',
                'new_node': new_node,
                'reason': f'line {raw_line} -> {matches[0]} (full file search)'
            }
        if len(matches) > 1:
            return {'strategy': 'multi_hit', 'new_node': node, 'reason': f'{len(matches)} matches in {filepath}'}

    repo_dir = fetch_repo_snapshot(repo_url, commit, repo_cache_dir)
    if repo_dir is None:
        return {'strategy': 'fetch_error', 'new_node': node, 'reason': f'failed to fetch repo snapshot for {commit}'}

    repo_result = search_code_in_repo(repo_dir, norm_code, filepath)
    if repo_result == 'multi_hit':
        return {'strategy': 'multi_hit', 'new_node': node, 'reason': 'multiple matches in repository'}
    if repo_result is not None:
        new_file, new_line = repo_result
        new_node = dict(node)
        new_node['file'] = new_file
        new_node['line'] = new_line
        if 'desc' in node and isinstance(node['desc'], str) and node['desc']:
            new_node['desc'] = sync_desc(
                node['desc'], filepath, new_file,
                line_start, line_end, new_line, new_line)
        return {
            'strategy': 'repo_search',
            'new_node': new_node,
            'reason': f'{filepath}:{raw_line} -> {new_file}:{new_line} (repository search)'
        }

    return {'strategy': 'not_found', 'new_node': node, 'reason': f'code not found in file or repository'}


def process_entry(entry: dict, repo_cache_dir: Path) -> dict:
    result = {'entry': dict(entry), 'fixes': [], 'needs_human': [], 'error': None}
    entry_id = entry.get('entry_id', 'unknown')
    repo_url = entry.get('repo_url', '')
    commit = entry.get('commit', '')
    if not repo_url or not commit:
        result['error'] = 'missing repo_url or commit'
        return result

    entry_copy = dict(entry)

    def _check_node(node, field_name):
        if not node or not isinstance(node, dict):
            return node
        vr = verify_node(repo_url, commit, node, repo_cache_dir)
        if vr['strategy'] in ('nearby_fix', 'file_search', 'repo_search'):
            result['fixes'].append({
                'entry_id': entry_id,
                'field': field_name,
                'original_file': node.get('file', ''),
                'original_line': node.get('line', ''),
                'original_desc': node.get('desc', ''),
                'new_file': vr['new_node'].get('file', ''),
                'new_line': vr['new_node'].get('line', ''),
                'new_desc': vr['new_node'].get('desc', ''),
                'strategy': vr['strategy'],
                'reason': vr['reason']
            })
            return vr['new_node']
        if vr['strategy'] in ('not_found', 'multi_hit', 'fetch_error', 'degenerate'):
            result['needs_human'].append({
                'entry_id': entry_id,
                'field': field_name,
                'node': node,
                'reason': vr['reason']
            })
        return node

    ep = entry_copy.get('entry_point')
    if ep and isinstance(ep, dict):
        entry_copy['entry_point'] = _check_node(ep, 'entry_point')

    co = entry_copy.get('critical_operation')
    if co and isinstance(co, dict):
        entry_copy['critical_operation'] = _check_node(co, 'critical_operation')

    trace = entry_copy.get('trace', [])
    if isinstance(trace, list):
        new_trace = []
        for idx, node in enumerate(trace):
            if isinstance(node, dict):
                new_trace.append(_check_node(node, f'trace[{idx}]'))
            else:
                new_trace.append(node)
        entry_copy['trace'] = new_trace

    result['entry'] = entry_copy
    return result


def main():
    parser = argparse.ArgumentParser(description='VulnGym Issue #4 — 修复代码片段定位偏差')
    parser.add_argument('--input', required=True, help='entries.jsonl 路径')
    parser.add_argument('--output', required=True, help='输出路径')
    parser.add_argument('--fix-diff', default='fix_diff.csv')
    parser.add_argument('--needs-human', default='needs_human.csv')
    parser.add_argument('--repo-cache-dir', default='.issue4_repo_cache', help='仓库快照缓存目录')
    parser.add_argument('--verify-only', action='store_true', help='仅处理 verify=0 条目')
    parser.add_argument('--dry-run', action='store_true', help='只分析不写文件')
    parser.add_argument('--verbose', '-v', action='store_true')
    parser.add_argument('--workers', type=int, default=DEFAULT_WORKERS, help='并行 worker 数')
    parser.add_argument('--limit', type=int, default=0, help='限制处理条数（调试用）')
    parser.add_argument('--no-cache', action='store_true', help='禁用 HTTP 和仓库缓存')
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f'Error: {args.input} not found')
        sys.exit(1)

    entries = []
    with input_path.open('r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                pass

    print(f'Loaded {len(entries)} entries')
    if args.verify_only:
        entries = [e for e in entries if e.get('verify') == 0]
        print(f'Filtered to {len(entries)} entries (verify=0)')
    if args.limit > 0:
        entries = entries[:args.limit]
        print(f'Limited to {len(entries)} entries')

    repo_cache_dir = Path(args.repo_cache_dir)
    if args.no_cache:
        _file_cache.clear()
        if repo_cache_dir.exists():
            shutil.rmtree(str(repo_cache_dir), ignore_errors=True)
    repo_cache_dir.mkdir(parents=True, exist_ok=True)

    start_time = time.time()
    all_fixes = []
    all_needs_human = []
    fixed_entries = []
    errors = []

    def worker(entry):
        return process_entry(entry, repo_cache_dir)

    n_workers = max(1, min(args.workers, len(entries) or 1))
    results = []
    if len(entries) <= 1:
        results = [worker(e) for e in entries]
    else:
        with ThreadPoolExecutor(max_workers=n_workers) as executor:
            futures = {executor.submit(worker, e): e for e in entries}
            for future in as_completed(futures):
                entry = futures[future]
                try:
                    results.append(future.result())
                except Exception as ex:
                    results.append({
                        'entry': entry,
                        'fixes': [],
                        'needs_human': [],
                        'error': str(ex)
                    })

    id_to_results = {}
    for result in results:
        eid = result['entry'].get('entry_id', '')
        id_to_results.setdefault(eid, []).append(result)

    for entry in entries:
        eid = entry.get('entry_id', '')
        bucket = id_to_results.get(eid, [])
        result = bucket.pop(0) if bucket else None
        if result is None:
            fixed_entries.append(entry)
            errors.append({'entry_id': eid, 'error': 'missing result'})
            continue
        fixed_entries.append(result['entry'])
        all_fixes.extend(result['fixes'])
        all_needs_human.extend(result['needs_human'])
        if result['error']:
            errors.append({'entry_id': eid, 'error': result['error']})

    elapsed = time.time() - start_time
    nearby_count = sum(1 for f in all_fixes if f['strategy'] == 'nearby_fix')
    file_count = sum(1 for f in all_fixes if f['strategy'] == 'file_search')
    repo_count = sum(1 for f in all_fixes if f['strategy'] == 'repo_search')
    desc_synced = sum(1 for f in all_fixes
                      if f.get('original_desc', '') != f.get('new_desc', ''))

    print(f"\n{'=' * 60}")
    print(f'  Processed {len(entries)} entries in {elapsed:.1f}s')
    print(f"{'=' * 60}")
    print(f'  Auto-fixed:  {len(all_fixes)}')
    print(f'    - nearby (+/-{SEARCH_RANGE}): {nearby_count}')
    print(f'    - file search:              {file_count}')
    print(f'    - repo search:              {repo_count}')
    print(f'    - desc sync:                 {desc_synced}')
    print(f'  Needs human: {len(all_needs_human)}')
    degenerate_count = sum(1 for nh in all_needs_human if nh.get('reason', '').startswith('degenerate'))
    if degenerate_count:
        print(f'    - degenerate snippets: {degenerate_count}')
    print(f'  Errors:      {len(errors)}')
    print(f"{'=' * 60}")

    if not args.dry_run:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open('w', encoding='utf-8') as f:
            for entry in fixed_entries:
                f.write(json.dumps(entry, ensure_ascii=False) + '\n')
        print(f'\n[OK] Fixed entries -> {args.output}')

        if all_fixes:
            with open(args.fix_diff, 'w', encoding='utf-8', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=[
                    'entry_id', 'field', 'original_file', 'original_line',
                    'original_desc', 'new_file', 'new_line', 'new_desc',
                    'strategy', 'reason'
                ])
                writer.writeheader()
                writer.writerows(all_fixes)
            print(f'[OK] Fix diff -> {args.fix_diff}')

        if all_needs_human:
            with open(args.needs_human, 'w', encoding='utf-8', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=[
                    'entry_id', 'field', 'file', 'line', 'code_preview', 'reason'
                ])
                writer.writeheader()
                for item in all_needs_human:
                    writer.writerow({
                        'entry_id': item['entry_id'],
                        'field': item['field'],
                        'file': item['node'].get('file', ''),
                        'line': item['node'].get('line', ''),
                        'code_preview': (item['node'].get('code', '') or '')[:100],
                        'reason': item['reason']
                    })
            print(f'[OK] Needs human -> {args.needs_human}')

        if errors:
            with open('fix_errors.csv', 'w', encoding='utf-8', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['entry_id', 'error'])
                writer.writeheader()
                writer.writerows(errors)
            print('[OK] Errors -> fix_errors.csv')

    print('\nDone.')


if __name__ == '__main__':
    main()
