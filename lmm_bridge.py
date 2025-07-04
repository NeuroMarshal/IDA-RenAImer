# lmm_bridge.py - Bridge between code, Ollama and Pydantic schemas

from __future__ import annotations
from typing import Any, Dict, List, Optional, Sequence
import json, re, types
import requests

from settings import AIAssistantSettings
from logger import log_info, log_debug, log_error, log_warning

# ────────────────────────── PromptBuilder ───────────────────────────────
class PromptBuilder:
    """Class for building prompts for code analysis"""

    def build_analysis_prompt(
        self,
        code: str,
        context: str,
        thinking_mode: bool = False,
        mode: str = "full",
    ) -> tuple[str, str]:
        """Create prompts for code analysis"""

        system_prompt = AIAssistantSettings.instance().get("system_prompt", "")
        base_user_prompt = AIAssistantSettings.instance().get("user_prompt", "")

        if thinking_mode:
            think_instruction = (
                "First, think through the code step by step in detail (≥ 8 sentences) and write the result in the **thinking** field. "
                "In the **reasoning** field, give a short (2-3 sentences) justification for all the names you chose. "
                "Then return **exactly one** JSON object with the schema: "
                "{thinking, reasoning, entrypoint, comment, variables, functions, structures}. "
                "No markdown or text outside the object."
            )
            system_prompt = f"{system_prompt}\n\n{think_instruction}"
            user_prompt = ""
        else:
            user_prompt = base_user_prompt

        if context:
            user_prompt += f"\n\nCONTEXT OF RELATED FUNCTIONS:\n{context}\n"

        user_prompt += f"\nCODE TO ANALYSE:\n{code}"
        return system_prompt, user_prompt


# ────────────────────────── OllamaClient ───────────────────────────────
class OllamaClient:
    """Client for interacting with the Ollama API"""

    def __init__(self):
        self.base_url = AIAssistantSettings.instance().get("ollama_url", "http://127.0.0.1:11434")

    def test_connection(self) -> tuple[bool, str]:
        try:
            url = f"{self.base_url.rstrip('/')}/api/version"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                version = response.json().get('version', 'unknown')
                return True, f"Connection successful (version: {version})"
            else:
                return False, f"HTTP {response.status_code}"
        except Exception as e:
            return False, str(e)

    def get_models(self) -> List[str]:
        try:
            url = f"{self.base_url.rstrip('/')}/api/tags"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                models = response.json().get("models", [])
                return [m["name"] for m in models]
            log_error(f"Failed to get models: HTTP {response.status_code}")
            return []
        except Exception as e:
            log_error(f"Failed to get models: {e}")
            return []

    def query_model(
        self,
        model_name: str,
        system_prompt: str,
        user_prompt: str,
        schema: Optional[Dict] = None,
        stream: bool = False,
        extra_body: Optional[Dict] = None,
    ):
        url = f"{self.base_url.rstrip('/')}/api/chat"
        payload = {
            "model": model_name,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt},
            ],
            "options": {
                "temperature": AIAssistantSettings.instance().get("temperature", 0.0),
                "seed":        AIAssistantSettings.instance().get("seed", 0),
                "num_ctx":     AIAssistantSettings.instance().get("num_ctx", 8192),
                "n_batch":     AIAssistantSettings.instance().get("n_batch", 512),
                "num_predict": AIAssistantSettings.instance().get("num_predict", 512),
            },
            "stream": False,
        }
        if extra_body:
            payload["options"].update(extra_body)
        payload["format"] = schema if schema else "json"
        try:
            log_debug(f"Sending request to {url}")
            resp = requests.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()
            content = data.get("message", {}).get("content", "")
            log_debug(content)
            log_debug(f"Received response of length {len(content)} characters")
            return content
        except requests.exceptions.ConnectionError as e:
            log_error(f"Connection error to Ollama: {e}")
            return None
        except requests.exceptions.HTTPError as e:
            log_error(f"HTTP error from Ollama: {e}")
            return None
        except Exception as e:
            log_error(f"Unexpected request error to Ollama: {e}")
            return None

    def update_settings(self):
        self.base_url = AIAssistantSettings.instance().get("ollama_url", "http://127.0.0.1:11434")

# ──────────────────── JSON parser ────────────────────────
class JSONParseError(RuntimeError):
    def __init__(self, stage: str, preview: str, total_len: int):
        super().__init__(f"[{stage}] cannot extract valid JSON")
        self.stage, self.preview, self.total_len = stage, preview, total_len

_WRAP = {"(": ")", "[": "]", "{": "}"}
_OPEN, _CLOSE = set(_WRAP), set(_WRAP.values())
_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.S | re.I)


def _flatten(resp: Any) -> str:
    if isinstance(resp, dict):
        if "message" in resp and isinstance(resp["message"], dict):
            return str(resp["message"].get("content", ""))
        return str(resp)
    if hasattr(resp, "message") and hasattr(resp.message, "content"):
        return str(resp.message.content or "")
    if isinstance(resp, str):
        return resp
    if isinstance(resp, (Sequence, types.GeneratorType)):
        return "".join(_flatten(c) for c in resp)
    return str(resp)


def _unescape(txt: str) -> str:
    if txt.startswith(("{\\", "[\\", "\"{\\", "\"[\\", "'{\\", "'[\\")):
        try:
            return bytes(txt, "utf-8").decode("unicode_escape")
        except Exception:
            pass
    return txt


def _strip_wrappers(txt: str) -> str:
    while txt and txt[0] in _OPEN and txt[-1] == _WRAP.get(txt[0], ""):
        inner = txt[1:-1].strip()
        try:
            json.loads(inner)
            return inner
        except Exception:
            txt = inner
    return txt


def _extract_block(txt: str) -> str:
    try:
        json.loads(txt)
        return txt
    except Exception:
        pass
    m = _FENCE_RE.search(txt)
    if m:
        candidate = m.group(1)
        try:
            json.loads(candidate)
            return candidate
        except Exception:
            pass
    first, last = txt.find("{"), txt.rfind("}")
    if first != -1 and last != -1 and last > first:
        candidate = txt[first:last + 1]
        try:
            json.loads(candidate)
            return candidate
        except Exception:
            pass
    return txt


def extract(raw: Any) -> Dict[str, Any]:
    try:
        txt = _flatten(raw)
        if not txt or not isinstance(txt, str):
            raise JSONParseError("flatten", str(type(txt)), 0)
        txt = _unescape(txt)
        txt = _strip_wrappers(txt)
        blob = _extract_block(txt)
        return json.loads(blob)
    except JSONParseError:
        raise
    except Exception as e:
        preview = (txt if "txt" in locals() else str(raw))[:512]
        raise JSONParseError("json.loads", preview, len(preview)) from e

from pydantic import BaseModel, Field

class EntryPointRename(BaseModel):
    original_name: str = Field(description="Original name for the function being analyzed from pseudocode")
    new_name: str = Field(description="A new descriptive name for the function being analyzed in snake_case format")

class VariableRename(BaseModel):
    original_name: str = Field(description="Original variable/parameter name from pseudocode (like a1, a2, v1, v2, v3, Block)")
    new_name: str = Field(description="New descriptive variable/parameter name in snake_case (like buffer_ptr, buffer_size, memory_ptr)")

class FunctionRename(BaseModel):
    original_name: str = Field(description="Original function name from pseudocode")
    new_name: str = Field(description="New descriptive function name in snake_case")

class StructureRename(BaseModel):
    original_name: str = Field(description="Original structure name")
    new_name: str = Field(description="New descriptive structure name")

class CodeAnalysis(BaseModel):
    # entrypoint: str = Field(description="A new descriptive name for the function being analyzed in snake_case format")
    entrypoint: EntryPointRename = Field(description="Renaming the function being analyzed (entry point) itself")
    comment: str = Field(description="Brief function description (2-4 sentences)")
    variables: List[VariableRename] = Field(description="All variables and parameters to rename (a1, a2, v1, v2, etc.)")
    functions: List[FunctionRename] = Field(description="All called functions to rename")
    structures: List[StructureRename] = Field(description="All structures to rename")

    def __str__(self):
        return (
            f"Function: {self.entrypoint}\n"
            f"Comment: {self.comment}\n"
            f"Vars: {len(self.variables)}\n"
            f"Funcs: {len(self.functions)}\n"
            f"Structs: {len(self.structures)}"
        )

class CodeAnalysisWithThinking(BaseModel):
    thinking: str = Field(description="Detailed step-by-step analysis about what the function does")
    reasoning: str = Field(description="Logical reasoning and justification for naming choices")
    entrypoint: EntryPointRename = Field(description="Renaming the function being analyzed (entry point) itself")
    comment: str = Field(description="Brief function description (2-4 sentences)")
    variables: List[VariableRename] = Field(description="All variables and parameters to rename (a1, a2, v1, v2, etc.)")
    functions: List[FunctionRename] = Field(description="All called functions to rename")
    structures: List[StructureRename] = Field(description="All structures to rename")

    def __str__(self):
        return (
            f"Function: {self.entrypoint}\n"
            f"Comment: {self.comment}\n"
            f"Vars: {len(self.variables)}\n"
            f"Funcs: {len(self.functions)}\n"
            f"Structs: {len(self.structures)}"
        )

def parse_analysis_response(raw_response, thinking_mode: bool = False) -> dict:
        try:
            try:
                parsed_data = extract(raw_response)
                log_debug("Successfully parsed JSON with extract")
            except JSONParseError as je:
                log_error(f"Parser failed at {je.stage}: {je.preview}...")
                text = _flatten(raw_response)
                parsed_data = json.loads(text)
            schema_model = CodeAnalysisWithThinking if thinking_mode else CodeAnalysis
            try:
                if hasattr(schema_model, "model_validate"):
                    analysis = schema_model.model_validate(parsed_data)
                else:
                    analysis = schema_model.parse_obj(parsed_data)
            except Exception as pydantic_error:
                if thinking_mode:
                    try:
                        analysis = CodeAnalysis.model_validate(parsed_data)
                        if "thinking" in parsed_data:
                            analysis.thinking = parsed_data["thinking"]
                        if "reasoning" in parsed_data:
                            analysis.reasoning = parsed_data["reasoning"]
                    except Exception:
                        raise pydantic_error
                else:
                    raise pydantic_error
            result = {
                "entrypoint": analysis.entrypoint.model_dump(),
                "comment": analysis.comment,
                "variables": [{"original_name": v.original_name, "new_name": v.new_name} for v in analysis.variables],
                "functions": [{"original_name": f.original_name, "new_name": f.new_name} for f in analysis.functions],
                "structures": [{"original_name": s.original_name, "new_name": s.new_name} for s in analysis.structures]
            }
            if hasattr(analysis, 'thinking'):
                result["thinking"] = analysis.thinking
            if hasattr(analysis, 'reasoning'):
                result["reasoning"] = analysis.reasoning
            return result
        except Exception as e:
            log_error(f"Pydantic validation failed: {e}")
            return {
                "entrypoint": {"original_name": "unknown", "new_name": "unknown_function"},
                "comment": "Error parsing model response",
                "variables": [],
                "functions": [],
                "structures": [],
                "error": str(e)
            }

def analyze_code(code: str, context: str, model_name: str, thinking_mode: bool = False) -> Optional[dict]:
    """Full cycle: build prompts → query Ollama → parse response"""

    prompt_builder = PromptBuilder()
    system_prompt, user_prompt = prompt_builder.build_analysis_prompt(code, context, thinking_mode)
    
    model_cls = CodeAnalysisWithThinking if thinking_mode else CodeAnalysis
    schema = model_cls.model_json_schema()
    if "required" in schema and isinstance(schema["required"], list):
        schema["required"] = list(dict.fromkeys(schema["required"]))
    
    ollama_client = OllamaClient()
    response = ollama_client.query_model(model_name, system_prompt, user_prompt, schema=schema)
    if not response:
        return None
    return parse_analysis_response(response, thinking_mode)
