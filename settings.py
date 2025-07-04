# settings.py - Manage settings via INI

import os
import json
from typing import Any

try:
    from PyQt5.QtCore import QSettings
    PYQT5_AVAILABLE = True
except ImportError:
    PYQT5_AVAILABLE = False

from logger import log_info, log_debug, log_error, log_warning

_settings_instance = None

class AIAssistantSettings:
    """Class for managing plugin settings with INI persistence"""
    
    def __init__(self):
        self._defaults = {
            # Ollama connection
            "ollama_url": "http://127.0.0.1:11434",
            "auto_discover_models": True,
            
            # Models
            "available_models": [],
            
            # Prompts
            "system_prompt": (
                "You are an experienced reverse-engineer. Analyse the Hex-Rays pseudocode and "
                "rename **every** identifier: the function itself, every parameter and local "
                "variable (a1, v1, Block …), every called function and every C-structure. "
                "Use clear descriptive **snake_case** names and Russian comments (1-3 sentences). "
                "Return exactly one JSON object with the fields: "
                "{entrypoint, comment, variables, functions, structures}."
            ),
            "user_prompt": (
                "Return STRICTLY one valid JSON object (no markdown, no commentary!) "
                "with the structure: "
                "{entrypoint, comment, variables, functions, structures}. "
                "In 'variables' include ALL parameters (a1, a2, ...) and local variables (v1, v2, v3, Block, ptr, ...). "
                "Represent every rename as "
                "[{\"original_name\": \"a1\", \"new_name\": \"buffer_size\"}, {\"original_name\": \"v2\", \"new_name\": \"result_ptr\"}] and use snake_case."
            ),
            
            # Debugging and limits
            "debug": 0,
            "comment_max_line_length": 128,
            "max_called_functions": 8,
            "max_calling_functions": 4,

            "thinking_mode": False,
            "display_thinking": False,
            "display_reasoning": False,
            
            # Functions
            "rename_structs": True,
            "rename_called_functions": True,
            
            # Ollama parameters
            "num_ctx": 8192,
            "n_batch": 512,
            # How many tokens the model can output (enough for long thinking)
            "num_predict": 8192,
            "temperature": 0.2,
            "seed": 0
        }

        self.settings = {}
        self._settings_file = os.path.join(os.path.dirname(__file__), "ai_assistant_settings.ini")
        if not os.path.exists(self._settings_file):
            self.settings = self._defaults.copy()
            self.save_settings()
            log_info("INI file created with default settings")
        self.load_settings()
    
    def load_settings(self):
        """Load settings from INI file"""
        if not PYQT5_AVAILABLE:
            self.settings = self._defaults.copy()
            return
            
        try:
            # Use QSettings with INI format
            qs = QSettings(self._settings_file, QSettings.IniFormat)
            qs.setIniCodec("UTF-8")
            
            # Load all settings
            for key, default_value in self._defaults.items():
                self.settings[key] = qs.value(key, default_value)
                
                # Convert types
                if isinstance(default_value, bool):
                    self.settings[key] = str(self.settings[key]).lower() == 'true'
                elif isinstance(default_value, int):
                    try:
                        self.settings[key] = int(self.settings[key])
                    except (ValueError, TypeError):
                        self.settings[key] = default_value
                elif isinstance(default_value, float):
                    try:
                        self.settings[key] = float(self.settings[key])
                    except (ValueError, TypeError):
                        self.settings[key] = default_value
                elif isinstance(default_value, list):
                    if isinstance(self.settings[key], str):
                        try:
                            self.settings[key] = json.loads(self.settings[key])
                        except Exception:
                            self.settings[key] = default_value
                            
        except Exception as e:
            log_error(f"Settings load error: {e}. Using default values.")
            self.settings = self._defaults.copy()
    
    def save_settings(self):
        """Save settings to INI file"""
        if not PYQT5_AVAILABLE:
            return
            
        try:
            qs = QSettings(self._settings_file, QSettings.IniFormat)
            qs.setIniCodec("UTF-8")
            
            for key, value in self.settings.items():
                if isinstance(value, list):
                    qs.setValue(key, json.dumps(value, ensure_ascii=False))
                else:
                    qs.setValue(key, value)
                    
            qs.sync()
            log_info("Settings saved to INI file")
            
        except Exception as e:
            log_error(f"Settings save error: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a setting value"""
        return self.settings.get(key, default)
    
    def set(self, key: str, value: Any):
        """Set a setting value"""
        self.settings[key] = value
    
    def reset_to_defaults(self):
        """Reset settings to defaults"""
        self.settings = self._defaults.copy()

    @staticmethod
    def instance() -> "AIAssistantSettings":
        """Return the single settings instance"""
        global _settings_instance
        if _settings_instance is None:
            _settings_instance = AIAssistantSettings()
        return _settings_instance
