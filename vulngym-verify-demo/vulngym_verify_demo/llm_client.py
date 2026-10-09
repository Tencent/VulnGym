# -*- coding: utf-8 -*-
"""LLM 客户端。

- 真实后端：QwenClient（DashScope）、DeepSeekClient、GLMClient（智谱）
- 离线后端：MockLLMClient，按 prompt 关键词返回受控 JSON
- 容错包装：ResilientLLMClient — 真实 LLM 报错自动降级到 SafeLLMClient
"""
from __future__ import annotations

import json
import math
import os
import re
import sys
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .prompts import (
    PROMPT_VERSIONS,
    SELF_CHECK_PROMPT,
    TRACE_OVERALL_PROMPT,
    VULN_TITLE_PROMPT,
    get_prompt_version,
    vuln_category_prompt,
)


@dataclass
class LLMMessage:
    role: str
    content: str


@dataclass
class ProvenancedResult:
    """单次 LLM 调用的结果及其 provenance。

    used_fallback=True 表示该次调用实际走了 Safe fallback。该标记是单次调用
    作用域，前一次调用的 fallback 状态不会污染后一次调用。
    """
    content: str
    used_fallback: bool = False


# ============================================================
# I4 新增：脱敏 + 结构化响应解析
# ============================================================

# 脱敏正则（参考 schema._sanitize_message，提到模块顶层）
_REDACT_RX = [
    # Query strings and diagnostics frequently expose credentials without a
    # provider-specific ``sk-`` prefix.
    (re.compile(r"(?i)\b(?:api[_-]?key|authorization|token|secret)\s*[:=]\s*['\"]?[^\s,&'\"]+"), "<redacted>"),
    (re.compile(r"[A-Za-z]:\\[^\s\"']+"), "<abspath>"),   # Windows 反斜杠
    (re.compile(r"[A-Za-z]:/[^\s\"']+"), "<abspath>"),    # Windows 正斜杠
    (re.compile(r"/(?:home|Users|var|tmp|opt|root)/[^\s\"']+"), "<abspath>"),  # POSIX
    # 32+ 字符的 hex/base64（词边界触发，避免误删短 hex 如 commit 8 位前缀）
    (re.compile(r"\b[A-Za-z0-9_/+=]{32,}\b"), "<redacted>"),
    # API key 常见前缀
    (re.compile(r"\b(?:sk-|Bearer\s+)[A-Za-z0-9_\-+/=]{8,}"), "<redacted>"),
]


def redact_text(text: str) -> str:
    """脱敏：移除绝对路径与 API key 风格字符串。

    不抛异常——任何输入都返回字符串。
    """
    if not text:
        return ""
    for rx, repl in _REDACT_RX:
        text = rx.sub(repl, text)
    return text


# 合法的 status 取值
_VALID_STATUS = {"correct", "incorrect", "uncertain"}
_JSON_FENCE_RX = re.compile(
    r"^\s*```(?:json)?\s*\r?\n(?P<body>.*?)\r?\n?```\s*$",
    re.IGNORECASE | re.DOTALL,
)


def parse_json_object(raw: Any) -> Dict[str, Any]:
    """Decode a provider JSON object, including an otherwise-valid code fence.

    GLM's OpenAI-compatible endpoint can return `````json`` fenced content
    despite an instruction to return JSON only.  Accept only a whole-response
    fence (rather than extracting arbitrary JSON from prose) so unrelated
    explanatory text never becomes a judgement by accident.
    """
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str):
        raise ValueError("LLM response is not a JSON string or object")
    text = raw.strip()
    match = _JSON_FENCE_RX.match(text)
    if match:
        text = match.group("body").strip()
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("LLM response JSON is not an object")
    return data


def parse_structured_response(raw: Any) -> Dict[str, Any]:
    """解析 LLM 原始输出（字符串）→ 统一 4 键结构。

    规则（I4 启动手册 §3.1）：
      - 合法 JSON → 校验 4 键；缺 evidence_refs 补 []；status 非法 → uncertain
      - 非法 JSON → uncertain + 默认 evidence
      - evidence 空 → 补默认文本（同时 status 降级为 uncertain 防编造证据）
      - confidence 限制到 [0, 1]
      - 所有 evidence 字段走 redact_text

    入参也可以是 dict（已 parse 过），便于单测与内部调用复用。
    """
    UNCERTAIN_FALLBACK = {
        "status": "uncertain",
        "confidence": 0.20,
        "evidence": "LLM output unparseable; cannot perform semantic judgement.",
        "evidence_refs": [],
    }
    try:
        data = parse_json_object(raw)
    except (json.JSONDecodeError, TypeError, ValueError):
        return UNCERTAIN_FALLBACK

    # status
    status = data.get("status", "uncertain")
    if status not in _VALID_STATUS:
        status = "uncertain"

    # confidence
    try:
        conf = float(data.get("confidence", 0.0))
    except (TypeError, ValueError):
        conf = 0.0
    conf = max(0.0, min(1.0, conf))

    # evidence
    evidence_raw = data.get("evidence", "") or ""
    if not isinstance(evidence_raw, str):
        evidence_raw = str(evidence_raw)
    evidence = redact_text(evidence_raw)
    if not evidence.strip():
        evidence = "LLM gave empty evidence; treating as uncertain."
        # 空 evidence 时 status 降级为 uncertain（防编造证据）
        if status == "correct":
            status = "uncertain"

    # evidence_refs（缺则补 []）
    refs = data.get("evidence_refs", [])
    if not isinstance(refs, list):
        refs = []
    # 每个 ref 走脱敏
    clean_refs = []
    for r in refs:
        if not isinstance(r, dict):
            continue
        s = r.get("source", "")
        if s not in {"advisory", "repository", "git"}:
            continue
        clean_refs.append({
            "source": s,
            "locator": redact_text(str(r.get("locator", ""))),
            "quote": redact_text(str(r.get("quote", ""))),
        })

    return {
        "status": status,
        "confidence": conf,
        "evidence": evidence,
        "evidence_refs": clean_refs,
    }


class LLMError(RuntimeError):
    pass


class BaseLLMClient:
    def chat(self, messages: List[LLMMessage], *, temperature: float = 0.0) -> str:  # pragma: no cover
        raise NotImplementedError

    def chat_with_provenance(
        self, messages: List[LLMMessage], *, temperature: float = 0.0,
    ) -> ProvenancedResult:
        """调用 chat 并返回带 provenance 的结果。

        默认实现视为 primary 成功（used_fallback=False）。SafeLLMClient 与
        ResilientLLMClient 覆写此方法以提供真实 fallback 标记。
        """
        return ProvenancedResult(content=self.chat(messages, temperature=temperature))

    @property
    def name(self) -> str:  # pragma: no cover
        return type(self).__name__


class QwenClient(BaseLLMClient):
    """DashScope OpenAI-compatible chat client."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: float = 30.0,
    ) -> None:
        self.api_key = api_key or os.environ.get("QWEN_API_KEY", "")
        self.base_url = (base_url or os.environ.get("QWEN_BASE_URL", "")).rstrip("/")
        self.model = model or os.environ.get("QWEN_MODEL", "qwen-turbo")
        self.timeout = timeout
        if not self.api_key:
            raise LLMError("QWEN_API_KEY not set")
        if not self.base_url:
            raise LLMError("QWEN_BASE_URL not set")

    def chat(self, messages: List[LLMMessage], *, temperature: float = 0.0) -> str:
        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "temperature": temperature,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
        }
        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=self.timeout)
        except requests.RequestException as e:
            raise LLMError(f"qwen network error: {e}") from e
        if resp.status_code >= 400:
            raise LLMError(f"qwen http {resp.status_code}")
        try:
            body = resp.json()
        except ValueError as e:
            raise LLMError("qwen returned invalid JSON") from e
        try:
            return body["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as e:
            raise LLMError("unexpected qwen response structure") from e

    @property
    def name(self) -> str:
        return f"QwenClient(model={self.model})"


class DeepSeekClient(BaseLLMClient):
    """DeepSeek OpenAI-compatible chat client.

    base_url: https://api.deepseek.com
    model:    deepseek-v4-pro / deepseek-coder / ...
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: float = 30.0,
    ) -> None:
        self.api_key = api_key or os.environ.get("DEEPSEEK_API_KEY", "")
        self.base_url = (base_url or os.environ.get("DEEPSEEK_BASE_URL", "")).rstrip("/")
        self.model = model or os.environ.get("DEEPSEEK_MODEL", "deepseek-v4-pro")
        self.timeout = timeout
        if not self.api_key:
            raise LLMError("DEEPSEEK_API_KEY not set")
        if not self.base_url:
            raise LLMError("DEEPSEEK_BASE_URL not set")

    def chat(self, messages: List[LLMMessage], *, temperature: float = 0.0) -> str:
        try:
            import requests  # type: ignore
        except ImportError as e:
            raise LLMError("requests not installed; pip install requests") from e

        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "temperature": temperature,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
        }
        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=self.timeout)
        except requests.RequestException as e:
            raise LLMError(f"deepseek network error: {e}") from e
        if resp.status_code >= 400:
            raise LLMError(f"deepseek http {resp.status_code}")
        try:
            body = resp.json()
        except ValueError as e:
            raise LLMError("deepseek returned invalid JSON") from e
        try:
            return body["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as e:
            raise LLMError("unexpected deepseek response structure") from e

    @property
    def name(self) -> str:
        return f"DeepSeekClient(model={self.model})"


class GLMClient(BaseLLMClient):
    """智谱 GLM OpenAI-compatible chat client.

    base_url: https://open.bigmodel.cn/api/paas/v4
    model:    glm-4.7-flash / glm-4-plus / glm-4-air ...
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: float = 30.0,
    ) -> None:
        self.api_key = api_key or os.environ.get("GLM_API_KEY", "")
        self.base_url = (base_url or os.environ.get("GLM_BASE_URL", "")).rstrip("/")
        self.model = model or os.environ.get("GLM_MODEL", "glm-4-flash")
        self.timeout = timeout
        if not self.api_key:
            raise LLMError("GLM_API_KEY not set")
        if not self.base_url:
            raise LLMError("GLM_BASE_URL not set")

    def chat(self, messages: List[LLMMessage], *, temperature: float = 0.0) -> str:
        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "temperature": temperature,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
        }

        # ``requests`` is convenient when installed, but the offline demo must
        # not require a package installation merely to use the configured GLM
        # endpoint.  The standard-library fallback keeps the same payload and
        # intentionally omits server response bodies from errors.
        try:
            import requests  # type: ignore
        except ImportError:
            try:
                from urllib import error as urlerror
                from urllib import request as urlrequest
                request = urlrequest.Request(
                    url,
                    data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                    headers=headers,
                    method="POST",
                )
                with urlrequest.urlopen(request, timeout=self.timeout) as response:
                    body = json.loads(response.read().decode("utf-8"))
            except urlerror.HTTPError as exc:
                raise LLMError(f"glm http {exc.code}") from exc
            except (urlerror.URLError, OSError, ValueError, UnicodeError) as exc:
                raise LLMError(f"glm network or response error: {type(exc).__name__}") from exc
        else:
            try:
                resp = requests.post(url, headers=headers, json=payload, timeout=self.timeout)
            except requests.RequestException as exc:
                raise LLMError(f"glm network error: {type(exc).__name__}") from exc
            if resp.status_code >= 400:
                raise LLMError(f"glm http {resp.status_code}")
            try:
                body = resp.json()
            except ValueError as exc:
                raise LLMError("glm returned invalid JSON") from exc
        try:
            return body["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as e:
            raise LLMError("unexpected glm response structure") from e

    @property
    def name(self) -> str:
        return f"GLMClient(model={self.model})"


class ScriptedMockLLMClient(BaseLLMClient):
    """受控答案 Mock：仅供 `--llm mock` 测试模式或单元测试使用。

    该客户端按 prompt 关键词返回**确定性**答案，目的是让流水线在没有 API key
    也能跑通；它的输出是"剧本答案"而非真实模型判断，**禁止**在生产 pipeline
    中作为真实 LLM 失败时的兜底（否则会编造证据）。
    """

    @staticmethod
    def _json(status: str, confidence: float, evidence: str) -> str:
        return json.dumps(
            {"status": status, "confidence": confidence, "evidence": evidence,
             "evidence_refs": []},
            ensure_ascii=False,
        )

    @staticmethod
    def _self_check(agree: bool, comment: str) -> str:
        return json.dumps(
            {"agree": agree, "comment": comment},
            ensure_ascii=False,
        )

    def chat(self, messages: List[LLMMessage], *, temperature: float = 0.0) -> str:
        prompt = "\n".join(m.content for m in messages)

        # ---- self-check（必须放最前：fields dump 里包含 "vuln_category_l1" 等，会被后续分支误匹配）----
        if "请复核" in prompt or "self-check" in prompt.lower() or \
           "self_check_judge" in prompt:
            return self._self_check(
                True,
                "各字段证据一致，未发现冲突（mock 自检）",
            )

        # ---- category ----
        if "vuln_category_l1" in prompt or "vuln_category_l2" in prompt or \
           "vuln_category_l1_judge" in prompt or "vuln_category_l2_judge" in prompt:
            m = re.search(r"vuln_category_l[12].*?expected\s*[:：]\s*\"?([^\"\n]+)", prompt)
            if not m:
                m = re.search(r"advisory_hint_l[12].*?[:：]\s*\"?([^\"\n]+)", prompt)
            expected = m.group(1).strip() if m else "未知"
            actual = re.search(r"actual\s*[:：]\s*\"?([^\"\n]+)", prompt)
            actual_val = actual.group(1).strip() if actual else "未知"
            if expected in actual_val or actual_val in expected:
                return self._json("correct", 0.85, f"实际值 {actual_val} 与公告提示 {expected} 语义一致")
            return self._json("incorrect", 0.80, f"实际值 {actual_val} 与公告提示 {expected} 不一致")

        # ---- title ----
        if "vuln_title" in prompt or "vuln_title_judge" in prompt:
            return self._json("correct", 0.75, "标题与公告核心语义一致（mock 判定）")

        # ---- vuln_ids ----
        if "vuln_ids" in prompt or "vuln_ids_judge" in prompt:
            return self._json("correct", 0.90, "CVE / GHSA 编号在公告缓存中找到（mock 判定）")

        # ---- trace summary ----
        if "trace 链路整体合理性" in prompt or "trace_overall_judge" in prompt or \
           "trace_overall" in prompt:
            return self._json("correct", 0.70, "trace 链路上下游语义连贯（mock 判定）")

        # ---- default ----
        return self._json("uncertain", 0.40, "mock fallback: 信息不足以给出高置信度判定")

    @property
    def name(self) -> str:
        return "ScriptedMockLLMClient"


# 向后兼容别名：旧名字仍可用，但显式标注"test only"。
MockLLMClient = ScriptedMockLLMClient  # noqa: E305  (alias kept for back-compat)


class SafeLLMClient(BaseLLMClient):
    """安全兜底：任何 prompt 都返回 uncertain + needs 证据。

    当真实 LLM（Qwen/GLM/DeepSeek）不可用、网络断、限流、403 时作为 fallback。
    与 ScriptedMockLLMClient 的关键区别是：本客户端**永远不会**返回受控正确
    答案，从而避免"编造证据"的扣分项。
    """

    _SAFE_RESPONSE = {
        "status": "uncertain",
        "confidence": 0.20,
        "evidence": (
            "LLM unavailable; cannot perform semantic judgement. "
            "needs: re-run with API key set, or supply a manual audit."
        ),
        "evidence_refs": [],
    }

    def chat(self, messages: List[LLMMessage], *, temperature: float = 0.0) -> str:
        prompt = "\n".join(m.content for m in messages)
        # self-check 走同样协议：保持结构对齐。
        if "请复核" in prompt or "self-check" in prompt.lower() or \
           "self_check_judge" in prompt:
            return json.dumps(
                {
                    "agree": False,
                    "comment": (
                        "LLM unavailable for self-check; "
                        "cannot confirm or revise prior judgements."
                    ),
                },
                ensure_ascii=False,
            )
        return json.dumps(self._SAFE_RESPONSE, ensure_ascii=False)

    def chat_with_provenance(
        self, messages: List[LLMMessage], *, temperature: float = 0.0,
    ) -> ProvenancedResult:
        # SafeLLMClient 本身就是 fallback，任何调用都标记为 used_fallback=True。
        return ProvenancedResult(
            content=self.chat(messages, temperature=temperature),
            used_fallback=True,
        )

    @property
    def name(self) -> str:
        return "SafeLLMClient"


class ResilientLLMClient(BaseLLMClient):
    """Per-request safe fallback for transient provider failures.

    A failed request is never retried: it immediately receives one safe
    ``uncertain`` fallback.  Crucially, that failure must not poison later,
    independent fields in the same JSONL batch.  Each later request is allowed
    one normal primary attempt, preserving the sequential/no-retry Standard
    protocol while containing transient timeouts to their own field.
    """

    def __init__(self, primary: BaseLLMClient, fallback: BaseLLMClient) -> None:
        self.primary = primary
        self.fallback = fallback
        self._degraded = False

    def chat(self, messages: List[LLMMessage], *, temperature: float = 0.0) -> str:
        return self.chat_with_provenance(messages, temperature=temperature).content

    def chat_with_provenance(
        self, messages: List[LLMMessage], *, temperature: float = 0.0,
    ) -> ProvenancedResult:
        try:
            content = self.primary.chat(messages, temperature=temperature)
            return ProvenancedResult(content=content, used_fallback=False)
        except Exception as e:
            self._degraded = True
            print(
                f"[warn] LLM {redact_text(str(self.primary.name))} failed: {redact_text(str(e))[:120]}\n"
                f"[warn] using {self.fallback.name} for this request only",
                file=sys.stderr,
                flush=True,
            )
            content = self.fallback.chat(messages, temperature=temperature)
            return ProvenancedResult(content=content, used_fallback=True)

    @property
    def name(self) -> str:
        return f"ResilientLLMClient(primary={self.primary.name}, fallback={self.fallback.name}, degraded={self._degraded})"

    @property
    def degraded(self) -> bool:
        return self._degraded


def make_client(prefer: str = "auto", *, timeout: float = 30.0) -> BaseLLMClient:
    """根据环境变量与 prefer 选择 LLM 实现。

    重要约束：
    - `ScriptedMockLLMClient`（及其别名 `MockLLMClient`）**只**在 `prefer == "mock"`
      时返回；其他所有模式（auto / qwen / glm / deepseek）失败时 fallback 必须是
      `SafeLLMClient`，避免"编造证据"扣分。
    - `auto` 模式优先级：DeepSeek → GLM → Qwen → SafeLLMClient。
    """
    if (
        not isinstance(timeout, (int, float))
        or isinstance(timeout, bool)
        or not math.isfinite(float(timeout))
        or timeout <= 0
    ):
        raise ValueError("timeout must be a positive number")
    prefer = (prefer or "auto").lower()
    if prefer == "mock":
        return ScriptedMockLLMClient()

    builders = {
        "qwen": lambda: _try_qwen(timeout),
        "glm": lambda: _try_glm(timeout),
        "deepseek": lambda: _try_deepseek(timeout),
    }
    if prefer in builders:
        primary = builders[prefer]()
        if primary is None:
            return SafeLLMClient()
        return ResilientLLMClient(primary=primary, fallback=SafeLLMClient())

    # auto：按 DeepSeek → GLM → Qwen 顺序尝试真实后端，最后兜底 SafeLLMClient。
    for builder in (
        lambda: _try_deepseek(timeout),
        lambda: _try_glm(timeout),
        lambda: _try_qwen(timeout),
    ):
        primary = builder()
        if primary is not None:
            return ResilientLLMClient(primary=primary, fallback=SafeLLMClient())
    return SafeLLMClient()


def _try_qwen(timeout: float = 30.0) -> Optional[BaseLLMClient]:
    if not (os.environ.get("QWEN_API_KEY") and os.environ.get("QWEN_BASE_URL")):
        return None
    try:
        return QwenClient(timeout=timeout)
    except LLMError as e:
        print(f"[warn] Qwen init failed: {redact_text(str(e))}", file=sys.stderr)
        return None


def _try_glm(timeout: float = 30.0) -> Optional[BaseLLMClient]:
    if not (os.environ.get("GLM_API_KEY") and os.environ.get("GLM_BASE_URL")):
        return None
    try:
        return GLMClient(timeout=timeout)
    except LLMError as e:
        print(f"[warn] GLM init failed: {redact_text(str(e))}", file=sys.stderr)
        return None


def _try_deepseek(timeout: float = 30.0) -> Optional[BaseLLMClient]:
    if not (os.environ.get("DEEPSEEK_API_KEY") and os.environ.get("DEEPSEEK_BASE_URL")):
        return None
    try:
        return DeepSeekClient(timeout=timeout)
    except LLMError as e:
        print(f"[warn] DeepSeek init failed: {redact_text(str(e))}", file=sys.stderr)
        return None
