#!/usr/bin/env python3
# simple_test_ai_v3.py  — extended JSON-schema test with rich thinking

from __future__ import annotations
import argparse, json, os, re, sys, time
from typing import Any, Dict, List

import requests

# ────────────────────────────────────────────────────────────────────────────
# Pydantic schema from the plugin
# ────────────────────────────────────────────────────────────────────────────
sys.path.append(os.path.dirname(__file__))
try:
    from lmm_bridge import CodeAnalysis, CodeAnalysisWithThinking
except Exception as e:
    raise RuntimeError("Install pydantic first") from e

# ────────────────────────────────────────────────────────────────────────────
# Constants and test code
# ────────────────────────────────────────────────────────────────────────────
OLLAMA_URL   = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
DEFAULT_MODEL = "qwen3:8b"

TEST_CODE = r"""
_QWORD *__fastcall sub_140026A70(_QWORD *a1, LPCWCH lpWideCharStr)
{
  LPCWCH v2; // rbx
  const WCHAR *v4; // r8
  int v5; // eax
  CHAR *lpMultiByteStr; // rax
  __int64 v7; // rdx
  …
}
""".strip()

CONTEXT = (
    "// sub_140018A10 — buffer manipulation function\n"
    "// WideCharToMultiByte — WinAPI for Unicode→ANSI conversion"
)

# ────────────────────────────────────────────────────────────────────────────
# Ollama client (new API ≥ 0.2)
# ────────────────────────────────────────────────────────────────────────────
class OllamaClient:
    def __init__(self, url: str = OLLAMA_URL, timeout: int = 90) -> None:
        self.base, self.timeout = url, timeout

    def _post(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        res = requests.post(f"{self.base}{path}", json=payload, timeout=self.timeout)
        res.raise_for_status()
        return res.json()

    def version(self) -> str:
        return requests.get(f"{self.base}/api/version", timeout=5).json()["version"]

    def tags(self) -> List[str]:
        return [m["name"] for m in self._post("/api/tags", {})["models"]]

    def chat(self, model: str, sys_prompt: str, usr_prompt: str,
             schema: Dict[str, Any] | None) -> str:
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": sys_prompt},
                {"role": "user",   "content": usr_prompt},
            ],
            "options": {
                "temperature": 0.25,   # slightly higher – generates more detail
                "num_ctx":     8192,
                "num_predict": 1024,   # room for thinking
            },
            "stream": False,
        }
        if schema:
            payload["format"] = schema
        return self._post("/api/chat", payload)["message"]["content"]

# ────────────────────────────────────────────────────────────────────────────
# Utilities
# ────────────────────────────────────────────────────────────────────────────
def fmt(title: str, text: str) -> None:
    print(f"\n{title}\n" + "-"*70)
    print(text)
    print("-"*70)

def extract_json(text: str) -> str:
    text = re.sub(r"```json\s*", "", text, flags=re.I)
    text = re.sub(r"\s*```", "", text).strip()
    start, end = text.find("{"), text.rfind("}")+1
    if start == -1 or end == 0:
        raise ValueError("JSON block not found in response")
    return text[start:end]

# ────────────────────────────────────────────────────────────────────────────
def run(model: str, with_thinking: bool) -> None:

    client = OllamaClient()
    print(f"🔗 Ollama {client.version()}  |  model = {model}")

    # --- prompts ------------------------------------------------------------
    system_prompt = (
        "You are an experienced reverse-engineer. Analyse the Hex-Rays pseudocode "
        "and rename EVERY identifier (function, params & locals, called functions, structs). "
        "Return EXACTLY one JSON object that matches the provided schema.\n\n"
        "For fields *thinking* and *reasoning* write at least **8 sentences each "
        "and ≥ 120 words total**, explaining step-by-step analysis and naming choices."
    )

    user_prompt = (
        f"CONTEXT OF RELATED FUNCTIONS:\n{CONTEXT}\n\n"
        f"CODE TO ANALYSE:\n{TEST_CODE}"
    )

    # --- schema -------------------------------------------------------------
    schema = (CodeAnalysisWithThinking.model_json_schema()
              if with_thinking else CodeAnalysis.model_json_schema())
    
    # Remove duplicates from "required" list if present
    if "required" in schema and isinstance(schema["required"], list):
        schema["required"] = list(dict.fromkeys(schema["required"]))

    # --- request ------------------------------------------------------------
    fmt("JSON SCHEMA", json.dumps(schema, ensure_ascii=False, indent=2))
    t0 = time.time()
    raw = client.chat(model, system_prompt, user_prompt, schema)
    print(f"\n⏱  Generation took {time.time()-t0:.1f}s")

    fmt("RAW RESPONSE", raw)
    obj = extract_json(raw)
    parsed = (CodeAnalysisWithThinking if with_thinking else CodeAnalysis
              ).model_validate_json(obj)

    # --- output -------------------------------------------------------------
    if with_thinking:
        fmt("🧠 THINKING", parsed.thinking)
        fmt("💡 REASONING", parsed.reasoning)

    fmt("SUMMARY",
        f"Function : {parsed.entrypoint}\n"
        f"Comment  : {parsed.comment}\n"
        f"Vars     : {len(parsed.variables)}\n"
        f"Funcs    : {len(parsed.functions)}\n"
        f"Structs  : {len(parsed.structures)}"
    )

# ────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=DEFAULT_MODEL, help="ollama tag (default qwen3:8b)")
    ap.add_argument("--bare", action="store_true", help="disable thinking/reasoning fields")
    args = ap.parse_args()
    run(args.model, not args.bare)
