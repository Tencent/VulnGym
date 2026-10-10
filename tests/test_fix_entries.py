import unittest
import sys
import json
import tempfile
import os
from pathlib import Path

# 把 scripts 目录加入路径，方便导入 fix_entries
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from fix_entries import (
    normalize_line_value, format_line_value,
    strip_cjk_comments, normalize_code, is_low_information,
    search_code_in_lines, search_code_in_file,
    sync_desc_location, validate_output,
)


class TestNormalizeLineValue(unittest.TestCase):
    """测试行号解析：int 和 "start-end" 字符串"""

    def test_int(self):
        self.assertEqual(normalize_line_value(97), (97, 97))

    def test_range_string(self):
        self.assertEqual(normalize_line_value('348-352'), (348, 352))

    def test_zero_invalid(self):
        self.assertIsNone(normalize_line_value(0))

    def test_negative_invalid(self):
        self.assertIsNone(normalize_line_value(-1))

    def test_bad_string(self):
        self.assertIsNone(normalize_line_value('abc'))

    def test_reverse_range_invalid(self):
        self.assertIsNone(normalize_line_value('5-3'))


class TestFormatLineValue(unittest.TestCase):
    """测试行号格式化输出"""

    def test_single_int_original(self):
        self.assertEqual(format_line_value(97, 97, 97), 97)

    def test_single_str_original(self):
        self.assertEqual(format_line_value(97, 97, '97'), '97')

    def test_range(self):
        self.assertEqual(format_line_value(348, 352, 348), '348-352')


class TestNormalizeCode(unittest.TestCase):
    """测试代码归一化：tab转空格、去行尾空白"""

    def test_tab_replaced(self):
        result = normalize_code('\t\tfoo()')
        self.assertNotIn('\t', result)

    def test_trailing_whitespace_removed(self):
        result = normalize_code('foo()   ')
        self.assertEqual(result, 'foo()')

    def test_multiline_tab(self):
        result = normalize_code('def foo():\n\treturn bar')
        self.assertNotIn('\t', result)
        self.assertIn('    ', result)  # tab → 4 spaces


class TestStripCJKComments(unittest.TestCase):
    """测试中文注释剥离"""

    def test_double_slash_cjk(self):
        code = 'tempDiv.innerHTML = html; // 设置innerHTML'
        result = strip_cjk_comments(code)
        self.assertNotIn('设置', result)
        self.assertIn('tempDiv.innerHTML = html;', result)

    def test_hash_cjk(self):
        code = 'x = 1  # 赋值操作'
        result = strip_cjk_comments(code)
        self.assertNotIn('赋值', result)

    def test_english_comment_kept(self):
        code = 'x = 1  # set value'
        result = strip_cjk_comments(code)
        self.assertIn('# set value', result)


class TestIsLowInformation(unittest.TestCase):
    """测试低信息量判断"""

    def test_empty(self):
        self.assertTrue(is_low_information(''))

    def test_too_short(self):
        self.assertTrue(is_low_information('ab'))

    def test_ellipsis(self):
        self.assertTrue(is_low_information('...'))
        self.assertTrue(is_low_information('…'))

    def test_normal_code(self):
        self.assertFalse(is_low_information('tempDiv.innerHTML = htmlContent;'))


class TestSearchCodeInLines(unittest.TestCase):
    """测试代码搜索逻辑"""

    def test_single_match(self):
        lines = ['line1', 'foo()', 'line3']
        self.assertEqual(search_code_in_lines(lines, 'foo()'), [2])

    def test_no_match(self):
        lines = ['line1', 'line2']
        self.assertEqual(search_code_in_lines(lines, 'xyz()'), [])

    def test_multiple_matches(self):
        lines = ['foo()', 'bar', 'foo()']
        self.assertEqual(search_code_in_lines(lines, 'foo()'), [1, 3])

    def test_range_constraint(self):
        lines = ['foo()', 'foo()', 'foo()']
        result = search_code_in_lines(lines, 'foo()', start_line=2, end_line=3)
        self.assertEqual(result, [2, 3])

    def test_multiline_match(self):
        lines = ['header', 'def foo():', '    return bar', 'footer']
        code = 'def foo():\n\treturn bar'
        self.assertEqual(search_code_in_lines(lines, code), [2])


class TestSearchCodeInFile(unittest.TestCase):
    """测试文件搜索（不双重读文件）"""

    def test_read_and_search(self):
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.py', delete=False, encoding='utf-8'
        ) as tf:
            tf.write('line1\nfoo()\nline3\n')
            path = tf.name
        try:
            self.assertEqual(search_code_in_file(path, 'foo()'), [2])
        finally:
            os.unlink(path)


class TestSyncDescLocation(unittest.TestCase):
    """测试 desc 文件名和行号同步"""

    def test_sync_file_and_line(self):
        desc = '参见 old.py 的行 97'
        result = sync_desc_location(desc, 'old.py', 'new.py', 97, 100)
        self.assertIn('new.py', result)
        self.assertIn('行 100', result)

    def test_empty_desc_unchanged(self):
        self.assertEqual(sync_desc_location('', 'a.py', 'b.py', 1, 2), '')


class TestValidateOutput(unittest.TestCase):
    """测试 Schema 校验（含 trace 节点）"""

    def _make_valid_entry(self):
        return {
            'entry_id': 'entry-00001',
            'report_id': 'GHSA-TEST',
            'repo_url': 'https://github.com/test/test',
            'commit': 'a' * 40,
            'entry_point': {'file': 'test.py', 'line': 10, 'code': 'x=1'},
            'critical_operation': {'file': 'test.py', 'line': 20, 'code': 'y=2'},
            'trace': [{'file': 'test.py', 'line': '15-18', 'code': 'z=3'}],
        }

    def test_valid_entry_no_errors(self):
        self.assertEqual(validate_output([self._make_valid_entry()]), [])

    def test_invalid_entry_point_line(self):
        entry = self._make_valid_entry()
        entry['entry_point']['line'] = 0
        self.assertTrue(len(validate_output([entry])) > 0)

    def test_invalid_trace_line(self):
        entry = self._make_valid_entry()
        entry['trace'][0]['line'] = -1
        errors = validate_output([entry])
        self.assertTrue(any('trace[0]' in e for e in errors))

    def test_missing_code_field(self):
        entry = self._make_valid_entry()
        del entry['entry_point']['code']
        errors = validate_output([entry])
        self.assertTrue(any('code' in e for e in errors))


if __name__ == '__main__':
    unittest.main()
