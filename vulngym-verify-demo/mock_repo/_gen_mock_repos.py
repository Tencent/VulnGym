"""生成 mock 仓库：每个项目 <project>/<commit>/<file>。

每个文件可能有多行 target（按行号顺序追加）。支持 overwrite=False/True。
"""
import os
import re

repo_root = r'D:\code\Tencent\VulnGym\vulngym-verify-demo\mock_repo'


def write_lines(rel_path, lines_with_line_no, header=None, overwrite=True):
    """lines_with_line_no: [(line_no, code_str), ...]"""
    parts = rel_path.replace('\\', '/').split('/')
    commit = parts[1]
    base = os.path.join(repo_root, parts[0], commit, *parts[2:-1])
    os.makedirs(base, exist_ok=True)
    fp = os.path.join(base, parts[-1])

    # 已存在内容（append 模式时需要）
    existing = []
    if os.path.exists(fp) and not overwrite:
        with open(fp, 'r', encoding='utf-8') as f:
            existing = f.readlines()

    # 构造新的完整行表
    new_lines = []
    if header is None:
        header = '// mock repo: {} @ {}\n'.format(parts[0], commit)
    new_lines.append(header)
    i = header.count('\n')
    sorted_targets = sorted(lines_with_line_no, key=lambda x: x[0])
    for ln, code in sorted_targets:
        while i < ln - 1:
            new_lines.append('// padding line {}\n'.format(i + 1))
            i += 1
        new_lines.append(code + '\n')
        i += 1
    # 覆盖写
    with open(fp, 'w', encoding='utf-8') as f:
        f.writelines(new_lines)

    # 验证
    with open(fp, 'r', encoding='utf-8') as f:
        arr = f.readlines()
    for ln, code in sorted_targets:
        print(fp, '-> line {} = {}'.format(ln, arr[ln - 1].rstrip()))


# ===== blog-platform / commit 1111111... =====
write_lines(
    'blog-platform/1111111111111111111111111111111111111111/src/handlers/comment.js',
    [(97, 'insertTextHandler(data.content);')],
)
write_lines(
    'blog-platform/1111111111111111111111111111111111111111/src/lib/RichTextInput.svelte',
    [
        (343, '    renderRichText(content);'),
        (348, '    tempDiv.innerHTML = htmlContent;'),
    ],
)

# ===== shell-runner / commit 2222222... =====
write_lines(
    'shell-runner/2222222222222222222222222222222222222222/src/api.js',
    [(42, 'spawn("sh", ["-c", cmd]);')],
)
write_lines(
    'shell-runner/2222222222222222222222222222222222222222/src/runner.js',
    [(250, 'child_process.exec(userInput);')],
)

# ===== cmd-typo / commit 3333333... =====
write_lines(
    'cmd-typo/3333333333333333333333333333333333333333/src/route.js',
    [(17, 'processCommand(req.query.cmd);')],
)
write_lines(
    'cmd-typo/3333333333333333333333333333333333333333/src/exec.js',
    [
        (30, '    return exec(cmd);'),
        (33, '    spawn("/bin/sh", [req.query.cmd]);'),
    ],
)

# ===== auth-svc / commit 4444444... =====
write_lines(
    'auth-svc/4444444444444444444444444444444444444444/src/middleware.js',
    [(88, 'checkRole(req.user, role);')],
)
write_lines(
    'auth-svc/4444444444444444444444444444444444444444/src/policy.js',
    [(156, 'if (user.role !== requiredRole) throw new Forbidden();')],
)

# ===== remaining public smoke entries: each keeps local source evidence =====
write_lines('user-api/5555555555555555555555555555555555555555/src/routes/user.js',
            [(12, 'getUserById(req.params.id);')])
write_lines('user-api/5555555555555555555555555555555555555555/src/user.js',
            [(85, 'const sql = buildQuery(id);'), (88, 'db.query(sql);')])
write_lines('code-sandbox/6666666666666666666666666666666666666666/src/api/execute.js',
            [(45, 'runCode(req.body.code);')])
write_lines('code-sandbox/6666666666666666666666666666666666666666/src/sandbox.js',
            [(120, 'eval(userCode);')])
write_lines('file-mgr/7777777777777777777777777777777777777777/src/routes/file.js',
            [(23, 'deleteFile(req.query.path);')])
write_lines('file-mgr/7777777777777777777777777777777777777777/src/cleanup.js',
            [(63, 'const filePath = buildPath(path);'), (66, 'fs.unlinkSync(filePath);')])
write_lines('oauth-provider/8888888888888888888888888888888888888888/src/routes/auth.js',
            [(77, 'handleCallback(req.query.redirect_uri);')])
write_lines('oauth-provider/8888888888888888888888888888888888888888/src/oauth.js',
            [(155, 'redirect(url);')])
write_lines('native-parser/9999999999999999999999999999999999999999/src/parser.js',
            [(18, 'parseData(req.body);'), (22, 'callNative(data);')])
write_lines('native-parser/9999999999999999999999999999999999999999/native/parser.c',
            [(234, 'memcpy(buf, input, len);')])
write_lines('token-api/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/src/middleware/auth.js',
            [(34, 'authenticate(req);')])
write_lines('token-api/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/src/auth.js',
            [(99, "res.setHeader('X-Token', token);")])

print('DONE')
