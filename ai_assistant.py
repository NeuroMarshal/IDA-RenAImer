import ida_kernwin
import ida_hexrays
import idaapi
import traceback
import time
import threading
from typing import Optional, List, Dict

from settings import AIAssistantSettings
from logger import log_info, log_debug, log_error, log_warning
from lmm_bridge import (
    OllamaClient,
    PromptBuilder,
    parse_analysis_response,
    CodeAnalysis,
    CodeAnalysisWithThinking,
)
from ida_interface import IDAInterface
from ui_dialog import AIAssistantSettingsDialog


class AIAssistantPlugin(idaapi.plugin_t):
    """Main class of the AI Assistant plugin"""
    
    flags = idaapi.PLUGIN_KEEP | idaapi.PLUGIN_HIDE
    comment = "AI Assistant for code analysis using Ollama"
    help = "AI Assistant plugin for analyzing code with Ollama AI models"
    wanted_name = "AI Assistant"
    wanted_hotkey = ""

    def __init__(self):
        self.ollama_client: Optional[OllamaClient] = None
        self.prompt_builder: Optional[PromptBuilder] = None
        self.ida_interface: Optional[IDAInterface] = None
        self.ui_hooks = None  # changed from hexrays_hooks to ui_hooks
        self.initialized = False
        self.force_keep = False  # flag to prevent termination
        self.discovered_models: List[Dict] = []  # cache of discovered models

    def init(self):
        """Plugin initialization"""
        try:
            log_info("Initializing plugin...")

            # initialize modules
            for attr, cls in {
                "ollama_client": OllamaClient,
                "prompt_builder": PromptBuilder,
                "ida_interface": IDAInterface,
            }.items():
                try:
                    setattr(self, attr, cls())
                except Exception as e:
                    log_error(f"{cls.__name__}: {e}")

            # update model list once
            self.update_discovered_models()

            # register actions
            self._register_actions()
            
            # install hooks
            self._install_hooks()
            
            # auto-update models on plugin load
            self._auto_update_models()
            
            self.initialized = True
            log_info("Plugin initialized successfully")
            
            # small delay for stabilization
            time.sleep(0.1)
            
            return idaapi.PLUGIN_KEEP
            
        except Exception as e:
            log_error(f"Initialization error: {e}")
            traceback.print_exc()
            return idaapi.PLUGIN_SKIP

    def _register_actions(self):
        """Register plugin actions"""
        try:
            log_debug("Registering actions...")
            
            # core actions without hotkeys
            actions_to_register = [
                ('ai_assistant:settings', 'AI Analyze Settings', SettingsHandler),
                ('ai_assistant:analyze_lite', 'Lite analysis', AnalyzeLiteHandler),
                ('ai_assistant:analyze_adv', 'Advanced analysis', AnalyzeAdvHandler),
            ]

            for action_id, caption, handler_cls in actions_to_register:
                handler = handler_cls()

                action_desc = idaapi.action_desc_t(
                    action_id,
                    caption,
                    handler,
                    "",
                    "",
                    199
                )
                result = idaapi.register_action(action_desc)
                log_debug(f"Registered {action_id}: {result}")

            self._register_model_actions(self._get_available_models())
            
            # add to various menus (same as original code)
            self._add_to_menus()
            
            log_debug("Actions registered")
            
        except Exception as e:
            log_error(f"Action registration error: {e}")
            traceback.print_exc()
            # do not interrupt initialization because of menu errors

    def _register_model_actions(self, models: List[Dict]):
        """Register analysis actions for each model"""
        for model in models:
            safe_model_name = model['name'].replace(':', '_').replace('/', '_').replace('.', '_')

            lite_action_id = f"ai_assistant:analyze_lite_{safe_model_name}"
            lite_handler = AnalyzeLiteModelHandler(model['name'])
            action_desc = idaapi.action_desc_t(
                lite_action_id,
                f"Lite analysis with {model['display_name']}",
                lite_handler,
                "",
                "",
                199
            )
            idaapi.register_action(action_desc)

            adv_action_id = f"ai_assistant:analyze_adv_{safe_model_name}"
            adv_handler = AnalyzeAdvModelHandler(model['name'])
            action_desc = idaapi.action_desc_t(
                adv_action_id,
                f"Advanced analysis with {model['display_name']}",
                adv_handler,
                "",
                "",
                199
            )
            idaapi.register_action(action_desc)

    def _install_hooks(self):
        """Install UI hooks"""
        try:
            log_debug("Installing UI hooks...")
            self.ui_hooks = UIHooks()
            result = self.ui_hooks.hook()
            log_debug(f"Hook installation result: {result}")
            if result:
                log_debug("UI hooks installed")
            else:
                log_debug("Warning - failed to install UI hooks")
        except Exception as e:
            log_error(f"Hook installation error: {e}")
            traceback.print_exc()
            # do not interrupt initialization due to hook errors

    def _discover_models(self) -> List[Dict]:
        """Automatically discover available Ollama models"""
        if not AIAssistantSettings.instance().get("auto_discover_models", True):
            return []
        
        try:
            import requests
            ollama_url = AIAssistantSettings.instance().get("ollama_url", "http://127.0.0.1:11434")
            resp = requests.get(f"{ollama_url.rstrip('/')}/api/tags", timeout=5)
            resp.raise_for_status()
            models = resp.json().get("models", [])
            
            discovered = []
            for m in models:
                name = m.get("name")
                if name:
                    discovered.append({
                        "name": name,
                        "display_name": name.split(":")[0].title(),
                        "enabled": True,
                        "thinking": False,
                        "auto_discovered": True
                    })
            
            log_debug(f"Discovered {len(discovered)} models")
            return discovered
            
        except Exception as e:
            log_error(f"Model discovery error: {e}")
            return []

    def update_discovered_models(self) -> None:
        """Update the cache of discovered models"""
        self.discovered_models = self._discover_models()

    def _get_available_models(self) -> List[Dict]:
        """Get the list of available models"""
        cfg_models = AIAssistantSettings.instance().get("available_models", [])
        discovered = self.discovered_models or []
        
        # merge models from config and discovered ones
        names = {m["name"] for m in cfg_models}
        combined = cfg_models + [d for d in discovered if d["name"] not in names]
        
        return [m for m in combined if m.get("enabled", True)]

    def _auto_update_models(self):
        """Automatically update models when the plugin loads"""
        try:
            log_debug("Auto-updating models...")
            if not AIAssistantSettings.instance().get("auto_discover_models", True):
                log_debug("Auto discovery of models is disabled")
                return
            
            self.update_discovered_models()
            discovered = self.discovered_models
            if discovered:
                existing_models = AIAssistantSettings.instance().get("available_models", [])
                existing_names = {m["name"] for m in existing_models}
                
                # add new models
                new_models = [m for m in discovered if m["name"] not in existing_names]
                if new_models:
                    all_models = existing_models + new_models
                    settings = AIAssistantSettings.instance()
                    settings.set("available_models", all_models)
                    settings.save_settings()
                    log_info(f"Added {len(new_models)} new models on load")
                else:
                    log_debug("No new models found")
            else:
                log_debug("No models discovered or an error occurred")
        except Exception as e:
            log_error(f"Auto-update models error: {e}")

    def _add_to_menus(self):
        """Add items to the Edit menu"""
        try:
            idaapi.attach_action_to_menu('Edit/', 'ai_assistant:settings', idaapi.SETMENU_APP)
        except Exception as e:
            log_error(f"menu attach error: {e}")


def _run_analysis_async(cfunc, system_prompt: str, user_prompt: str, thinking_mode: bool, model_name: str, schema):
    """Run analysis in a separate thread without blocking the UI"""

    def worker():
        try:
            log_debug("AI analysis...")
            
            # determine parameters for the model
            extra_body = None
            # for think models we could control thinking mode
            # left empty for now but the feature is ready
            if thinking_mode:
                # could add: extra_body = {"enable_thinking": True}
                pass
            
            full_response = ai_plugin.ollama_client.query_model(
                model_name, system_prompt, user_prompt, schema=schema, extra_body=extra_body
            )
            log_info("Analysis complete")
            if not full_response:
                log_error("Failed to get response from AI model")
                return
            result = parse_analysis_response(full_response, thinking_mode)
            if not result or result.get("entrypoint") == "unknown_function":
                log_error("Failed to parse JSON response")
                return
            else:
                log_debug("JSON recognized successfully")

            def apply():
                ai_plugin.ida_interface.apply_analysis_results(cfunc, result)
                if AIAssistantSettings.instance().get("display_thinking", False) and "thinking" in result:
                    log_info(f"THINKING: {result['thinking']}")
                if AIAssistantSettings.instance().get("display_reasoning", False) and "reasoning" in result:
                    log_info(f"REASONING: {result['reasoning']}")
                log_debug("Function analysis finished")

            ida_kernwin.execute_sync(apply, ida_kernwin.MFF_FAST)
        except Exception as e:
            log_error(f"Analysis error: {e}")
            traceback.print_exc()

    threading.Thread(target=worker, daemon=True).start()

class BaseAnalyzeHandler(idaapi.action_handler_t):
    """Base handler for function analysis"""

    def __init__(self, model_name: Optional[str] = None, mode: str = "lite"):
        super().__init__()
        self.model_name = model_name
        self.mode = mode

    def activate(self, ctx):
        if not ai_plugin.initialized:
            log_error("not initialized")
            return 0
        ea = ida_kernwin.get_screen_ea()
        if ea == idaapi.BADADDR:
            log_error("Failed to get current address")
            return 0
        ida_kernwin.execute_sync(lambda: self._analyze(ea), ida_kernwin.MFF_FAST)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

    def _get_thinking_mode_for_model(self, model_name: str) -> bool:
        available_models = ai_plugin._get_available_models() if ai_plugin else []
        for model in available_models:
            if model.get("name") == model_name:
                return model.get("thinking", False)
        return False

    def _analyze(self, ea):
        try:
            cfunc = ida_hexrays.decompile(ea)
            code = str(cfunc)
        except ida_hexrays.DecompilationFailure:
            log_error("Failed to decompile function")
            return

        try:
            stats = ai_plugin.ida_interface.get_function_stats(cfunc)
        except Exception as e:
            log_error(f"Failed to get stats for function '{getattr(cfunc, 'name', cfunc)}': {e}")
            return

        # take values considering possible missing keys
        variables = stats.get('variables', 0)
        functions = stats.get('functions', 0)
        structures = stats.get('structures', 0)

        # compose message
        message = (
            f"Found in function: "
            f"{variables} variable{'s' if variables != 1 else ''}, "
            f"{functions} function{'s' if functions % 10 in (2,3,4) and functions not in (12,13,14) else ''}, "
            f"{structures} structure{'s' if structures % 10 in (2,3,4) and structures not in (12,13,14) else ''}."
        )

        log_info(message)

        context_text = ""
        if self.mode == "adv":
            ctx = ai_plugin.ida_interface.get_function_context(ea)
            context_text = ctx.get("text", "") if ctx else ""
            if ctx:
                log_info(
                    f"Context: {ctx.get('called',0)} called and {ctx.get('calling',0)} calling functions"
                )

        model_name = self.model_name or ""
        if not model_name:
            log_error("No AI model selected")
            return
        thinking_mode = self._get_thinking_mode_for_model(model_name)

        system_prompt, user_prompt = ai_plugin.prompt_builder.build_analysis_prompt(
            code, context_text, thinking_mode=thinking_mode, mode=self.mode
        )
        log_debug(f"System prompt: {system_prompt}")
        log_debug(f"User prompt: {user_prompt}")
        prompt_len = len(system_prompt) + len(user_prompt)
        log_info(f"Prompt length is {prompt_len} characters")
        log_debug("Prompt sent to model")
        schema = (
            CodeAnalysisWithThinking.model_json_schema()
            if thinking_mode
            else CodeAnalysis.model_json_schema()
        )
        log_info(f"AI {'advanced ' if self.mode == 'adv' else ''}analysis with {model_name}...")
        _run_analysis_async(
            cfunc,
            system_prompt,
            user_prompt,
            thinking_mode,
            model_name,
            schema,
        )

class AnalyzeLiteHandler(BaseAnalyzeHandler):
    """Lite analysis of the current function"""

    def __init__(self):
        super().__init__(mode="lite")

class AnalyzeLiteModelHandler(BaseAnalyzeHandler):
    """Lite analysis with a specific model"""

    def __init__(self, model_name: str):
        super().__init__(model_name=model_name, mode="lite")

class AnalyzeAdvHandler(BaseAnalyzeHandler):
    """Advanced analysis with full context"""

    def __init__(self):
        super().__init__(mode="adv")

class AnalyzeAdvModelHandler(BaseAnalyzeHandler):
    """Advanced analysis with a specific model"""

    def __init__(self, model_name: str):
        super().__init__(model_name=model_name, mode="adv")

class SettingsHandler(idaapi.action_handler_t):
    """Handler for opening the settings dialog"""

    def activate(self, ctx):
        try:
            dlg = AIAssistantSettingsDialog()
            dlg.exec_()
            return 1
        except Exception as e:
            log_error(f"Settings dialog error: {e}")
            traceback.print_exc()
            return 0

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class RefreshModelsHandler(idaapi.action_handler_t):
    """Refresh the model list at user request"""

    def activate(self, ctx):
        try:
            ai_plugin._auto_update_models()
            ai_plugin._register_model_actions(ai_plugin._get_available_models())
            log_info("Model list refreshed")
            return 1
        except Exception as e:
            log_error(f"Model refresh error: {e}")
            return 0

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class UIHooks(ida_kernwin.UI_Hooks):
    """Create exactly two menu branches: Lite / Advanced"""

    def finish_populating_widget_popup(self, widget, popup):
        """Add items to the decompiler context menu"""
        try:
            # verify that this is a pseudocode window
            if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_PSEUDOCODE:
                log_debug("Adding items to pseudocode context menu")
                
                menu_root = "AI Assistant/"
                lite_root = f"{menu_root}Lite analysis/"
                adv_root  = f"{menu_root}Advanced analysis/"

                # create subfolders (empty placeholders)
                ida_kernwin.attach_action_to_popup(widget, popup, None, lite_root)
                ida_kernwin.attach_action_to_popup(widget, popup, None, adv_root)

                # add models to the analysis submenu
                available_models = ai_plugin._get_available_models() if ai_plugin else []
                for model in available_models:
                    if not model.get("enabled", True):
                        continue  # skip disabled models
                        
                    safe_model_name = model['name'].replace(':', '_').replace('/', '_').replace('.', '_')
                    
                    # Lite analysis
                    lite_action_id = f"ai_assistant:analyze_lite_{safe_model_name}"
                    ida_kernwin.attach_action_to_popup(widget, popup, lite_action_id, lite_root)
                    
                    # Advanced analysis
                    adv_action_id = f"ai_assistant:analyze_adv_{safe_model_name}"
                    ida_kernwin.attach_action_to_popup(widget, popup, adv_action_id, adv_root)
                
                log_debug("Menu items added")
        except Exception as e:
            log_error(f"Context menu error: {e}")

ai_plugin = None

def PLUGIN_ENTRY():
    """Entry point for IDA Pro."""
    global ai_plugin
    ai_plugin = AIAssistantPlugin()
    try:
        return ai_plugin
    except Exception as e:
        log_error(f"Plugin creation error: {e}")
        return None

# For direct run from IDA
if __name__ == "__main__":
    plugin = PLUGIN_ENTRY()
    if plugin:
        plugin.init()

