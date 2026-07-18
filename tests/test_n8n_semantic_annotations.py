import json
import os
import re
import unittest
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "entries.jsonl"
REPORTS_PATH = ROOT / "data" / "reports.jsonl"
TARGET_IDS = {
    "entry-00099",
    "entry-00100",
    "entry-00103",
    "entry-00176",
    "entry-00182",
    "entry-00191",
    "entry-00511",
    "entry-00512",
}


ANCHORS = {
    "entry-00099": {
        "entry_point": (
            "packages/cli/src/workflows/workflows.controller.ts",
            539,
            "\t@Post('/:workflowId/run')",
        ),
        "critical_operation": (
            "packages/workflow/src/expression-evaluator-proxy.ts",
            "19-20",
            "export const evaluateExpression: Evaluator = (expr, data) => {\n"
            "\treturn evaluator(expr, data);",
        ),
        "trace_end": (
            "packages/workflow/src/expression-evaluator-proxy.ts",
            "19-20",
        ),
    },
    "entry-00100": {
        "entry_point": (
            "packages/workflow/src/expression.ts",
            "368-382",
            "\tresolveSimpleParameterValue(\n"
            "\t\tparameterValue: NodeParameterValue,\n"
            "\t\tsiblingParameters: INodeParameters,\n"
            "\t\trunExecutionData: IRunExecutionData | null,\n"
            "\t\trunIndex: number,\n"
            "\t\titemIndex: number,\n"
            "\t\tactiveNodeName: string,\n"
            "\t\tconnectionInputData: INodeExecutionData[],\n"
            "\t\tmode: WorkflowExecuteMode,\n"
            "\t\tadditionalKeys: IWorkflowDataProxyAdditionalKeys,\n"
            "\t\texecuteData?: IExecuteData,\n"
            "\t\treturnObjectAsString = false,\n"
            "\t\tselfData = {},\n"
            "\t\tcontextNodeName?: string,\n"
            "\t): NodeParameterValue | INodeParameters | NodeParameterValue[] | INodeParameters[] {",
        ),
        "critical_operation": (
            "packages/workflow/src/expression-evaluator-proxy.ts",
            "19-20",
            "export const evaluateExpression: Evaluator = (expr, data) => {\n"
            "\treturn evaluator(expr, data);",
        ),
        "trace_end": (
            "packages/workflow/src/expression-evaluator-proxy.ts",
            "19-20",
        ),
    },
    "entry-00103": {
        "entry_point": (
            "packages/cli/src/webhooks/webhook-request-handler.ts",
            "146-150",
            "\tprivate setResponseHeaders(res: express.Response, headers?: WebhookResponseHeaders) {\n"
            "\t\tif (headers) {\n"
            "\t\t\tfor (const [name, value] of headers.entries()) {\n"
            "\t\t\t\tres.setHeader(name, value);\n"
            "\t\t\t}",
        ),
        "critical_operation": (
            "packages/core/src/html-sandbox.ts",
            20,
            "\tconst contentTypeLower = contentType.toLowerCase();",
        ),
        "trace_end": ("packages/core/src/html-sandbox.ts", "19-25"),
    },
    "entry-00176": {
        "entry_point": (
            "packages/nodes-base/nodes/Code/Code.node.ts",
            206,
            "\t\t\tconst code = this.getNodeParameter(codeParameterName, 0) as string;",
        ),
        "critical_operation": (
            "packages/@n8n/task-runner-python/src/task_analyzer.py",
            66,
            "        if node.attr in BLOCKED_ATTRIBUTES:",
        ),
        "trace_end": (
            "packages/@n8n/task-runner-python/src/task_executor.py",
            213,
        ),
    },
    "entry-00182": {
        "entry_point": (
            "packages/nodes-base/nodes/Code/Code.node.ts",
            206,
            "\t\t\tconst code = this.getNodeParameter(codeParameterName, 0) as string;",
        ),
        "critical_operation": (
            "packages/@n8n/task-runner-python/src/task_analyzer.py",
            66,
            "        if node.attr in BLOCKED_ATTRIBUTES:",
        ),
        "trace_end": (
            "packages/@n8n/task-runner-python/src/task_executor.py",
            213,
        ),
    },
    "entry-00191": {
        "entry_point": (
            "packages/nodes-base/nodes/Form/utils/utils.ts",
            "590-605",
            "\tconst options = context.getNodeParameter('options', {}) as {\n"
            "\t\tignoreBots?: boolean;\n"
            "\t\tipWhitelist?: string;\n"
            "\t\trespondWithOptions?: {\n"
            "\t\t\tvalues: {\n"
            "\t\t\t\trespondWith: 'text' | 'redirect';\n"
            "\t\t\t\tformSubmittedText: string;\n"
            "\t\t\t\tredirectUrl: string;\n"
            "\t\t\t};\n"
            "\t\t};\n"
            "\t\tformSubmittedText?: string;\n"
            "\t\tuseWorkflowTimezone?: boolean;\n"
            "\t\tappendAttribution?: boolean;\n"
            "\t\tbuttonLabel?: string;\n"
            "\t\tcustomCss?: string;\n"
            "\t};",
        ),
        "critical_operation": (
            "packages/nodes-base/nodes/Form/utils/utils.ts",
            149,
            "\t\ttextFilter: (text) => text.replace(/&gt;/g, '>').replace(/&lt;/g, '<').replace(/&amp;/g, '&'),",
        ),
        "trace_end": (
            "packages/nodes-base/nodes/Form/utils/utils.ts",
            "141-150",
        ),
    },
    "entry-00511": {
        "entry_point": (
            "packages/workflow/src/expression.ts",
            "451-455",
            "\tresolveSimpleParameterValue(\n"
            "\t\tparameterValue: NodeParameterValue,\n"
            "\t\tdata: IWorkflowDataProxyData,\n"
            "\t\treturnObjectAsString = false,\n"
            "\t): NodeParameterValue | INodeParameters | NodeParameterValue[] | INodeParameters[] {",
        ),
        "critical_operation": (
            "packages/@n8n/expression-runtime/src/extensions/extend.ts",
            "132-134",
            "\tif (foundFunction.type === 'native') {\n"
            "\t\t// eslint-disable-next-line @typescript-eslint/no-unsafe-return\n"
            "\t\treturn foundFunction.function.apply(input, args);",
        ),
        "trace_end": (
            "packages/@n8n/expression-runtime/src/extensions/extend.ts",
            "132-134",
        ),
    },
    "entry-00512": {
        "entry_point": (
            "packages/workflow/src/expression.ts",
            "451-455",
            "\tresolveSimpleParameterValue(\n"
            "\t\tparameterValue: NodeParameterValue,\n"
            "\t\tdata: IWorkflowDataProxyData,\n"
            "\t\treturnObjectAsString = false,\n"
            "\t): NodeParameterValue | INodeParameters | NodeParameterValue[] | INodeParameters[] {",
        ),
        "critical_operation": (
            "packages/@n8n/expression-runtime/src/runtime/reset.ts",
            46,
            "\tglobalThis.__data.__sanitize = __sanitize;",
        ),
        "trace_end": (
            "packages/@n8n/expression-runtime/src/runtime/reset.ts",
            "42-46",
        ),
    },
}


def read_jsonl(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def normalize_span(line):
    if isinstance(line, int):
        return line, line
    start, end = line.split("-", 1)
    return int(start), int(end)


class SemanticAnnotationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.entries = read_jsonl(DATA_PATH)
        cls.by_id = {entry["entry_id"]: entry for entry in cls.entries}

    def test_dataset_shape_and_schema(self):
        self.assertEqual(len(self.entries), 408)
        self.assertEqual(len(self.by_id), len(self.entries))
        reports = read_jsonl(REPORTS_PATH)
        report_by_id = {report["report_id"]: report for report in reports}
        self.assertEqual(len(report_by_id), 184)

        grouped = defaultdict(list)
        for entry in self.entries:
            self.assertEqual(list(entry), sorted(entry))
            self.assertEqual(entry["origin"], "GitHub Advisory Database (reviewed)")
            self.assertRegex(entry["commit"], r"^[0-9a-f]{40}$")
            self.assertTrue(entry["repo_url"].startswith("https://github.com/"))
            self.assertIn(entry["report_id"], report_by_id)
            self.assertIn(entry["report_id"].lower(), entry["source_link"].lower())
            self.assertIn(entry["verify"], (0, 1))
            grouped[entry["report_id"]].append(entry["entry_id"])

            for field in ("entry_point", "critical_operation"):
                self._assert_node_shape(entry[field])
            for trace_node in entry["trace"]:
                self._assert_node_shape(trace_node)

        for report_id, report in report_by_id.items():
            self.assertEqual(report["entry_ids"], sorted(grouped[report_id]))
            self.assertEqual(report["num_entries"], len(grouped[report_id]))

    def test_all_target_entries_are_present_and_unverified(self):
        self.assertEqual(set(self.by_id) & TARGET_IDS, TARGET_IDS)
        for entry_id in TARGET_IDS:
            self.assertEqual(self.by_id[entry_id]["verify"], 0, entry_id)

    def test_semantic_anchors_and_trace_endpoints(self):
        for entry_id, expected in ANCHORS.items():
            entry = self.by_id[entry_id]
            for field in ("entry_point", "critical_operation"):
                actual = entry[field]
                expected_file, expected_line, expected_code = expected[field]
                self.assertEqual(actual["file"], expected_file, entry_id)
                self.assertEqual(actual["line"], expected_line, entry_id)
                self.assertEqual(actual["code"], expected_code, entry_id)

            trace_end = entry["trace"][-1]
            self.assertEqual((trace_end["file"], trace_end["line"]), expected["trace_end"], entry_id)
            critical = entry["critical_operation"]
            critical_start, critical_end = normalize_span(critical["line"])
            self.assertTrue(
                any(
                    node["file"] == critical["file"]
                    and normalize_span(node["line"])[0] <= critical_start
                    and normalize_span(node["line"])[1] >= critical_end
                    for node in entry["trace"]
                ),
                entry_id,
            )

    def test_only_target_entries_changed_when_base_is_available(self):
        base_path = os.environ.get("VULNGYM_BASE_ENTRIES")
        if base_path:
            candidate = Path(base_path)
        else:
            sibling = ROOT.parent / "VulnGym" / "data" / "entries.jsonl"
            candidate = sibling
        if not candidate.exists():
            self.skipTest("set VULNGYM_BASE_ENTRIES to enable baseline diff check")

        base_entries = read_jsonl(candidate)
        self.assertEqual(len(base_entries), len(self.entries))
        changed = {
            old["entry_id"]
            for old, new in zip(base_entries, self.entries)
            if old != new
        }
        self.assertEqual(changed, TARGET_IDS)

    def test_cached_n8n_source_nodes_when_cache_is_available(self):
        cache_root = os.environ.get("VULNGYM_N8N_SOURCE_CACHE")
        if not cache_root:
            self.skipTest("set VULNGYM_N8N_SOURCE_CACHE to enable source matching")
        cache_root = Path(cache_root)

        checked = 0
        for entry_id in TARGET_IDS:
            entry = self.by_id[entry_id]
            for node in (
                entry["entry_point"],
                entry["critical_operation"],
                *entry["trace"],
            ):
                source_path = cache_root / entry["commit"] / node["file"]
                if not source_path.exists():
                    self.skipTest(f"missing cached source: {source_path}")
                lines = source_path.read_text(encoding="utf-8").splitlines()
                start, end = normalize_span(node["line"])
                actual = "\n".join(lines[start - 1 : end])
                self.assertEqual(actual, node["code"], f"{entry_id}: {node['file']}:{node['line']}")
                checked += 1

        self.assertEqual(checked, 61)

    def _assert_node_shape(self, node):
        required = {"file", "line", "code"}
        allowed = required | {"desc"}
        self.assertTrue(required <= set(node) <= allowed)
        start, end = normalize_span(node["line"])
        self.assertGreaterEqual(start, 1)
        self.assertLessEqual(start, end)


if __name__ == "__main__":
    unittest.main()
