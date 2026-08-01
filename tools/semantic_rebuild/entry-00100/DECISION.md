# entry-00100

## 采用

- entry_point：`expression.ts:368` `resolveSimpleParameterValue`（原标注可用）
- critical：同 00099，`evaluateExpression`
- verify：0

## 不采用

- 原 critical `sanitizer` 函数定义：逃逸时常调不到；且属 sanitizer 定义族
- `defineProperty(__sanitize)` 升 critical：装配点

候选表见 `CANDIDATES.md`；与 00099 共享 sink/缺陷争议处理。
