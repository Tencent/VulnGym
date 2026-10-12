# fetch_failed 解惑（entry-00097 / 00098）

## 原记录

全量跑时两条记入 `needs_human.csv`：

- AutoGPT @ `f0c25036082a5e53650ae7230bcfcf9309bbb5d5`
- 原因：`git checkout --force` exit 128

## 根因（不是 commit 丢失）

Windows 下路径过长：

`Filename too long ... ScheduleAgentModal/...`

`git cat-file` 显示 commit **已在本地**；失败发生在检出工作区文件树。

## 修复

```text
git -C .repo_cache/Significant-Gravitas__AutoGPT config core.longpaths true
git -C .repo_cache/Significant-Gravitas__AutoGPT checkout --force f0c25036082a5e53650ae7230bcfcf9309bbb5d5
```

重跑（旁路 out，不污染主 CSV）：

```text
python tools/fix_locations/fix_code_locations.py --only entry-00097 entry-00098 --apply --out tools/fix_locations/out/fetch_retry
→ fixed=0 needs_human=0
```

含义：checkout 成功后，全部节点已是 **already_matches**，无需改 file/line。  
主 `needs_human.csv` 里的两条 `repo_fetch_failed` 属于 **环境假阳性**，开 PR 前应从人工队列剔除或重跑导出。

## 脚本侧建议（可选后续 GREEN）

在 `ensure_repo` 里对 Windows 设置 `core.longpaths true`，避免再踩坑。
