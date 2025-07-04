# logger.py - Unified logging system for AI Assistant

import ida_kernwin

def log_info(message: str):
    """Output informational message (always shown)"""
    try:
        ida_kernwin.msg(f"[AI ASSISTANT INFO] {message}\n")
    except Exception:
        print(f"[AI ASSISTANT INFO] {message}")

def log_debug(message: str):
    """Output debug information (only when debug mode is enabled)"""
    try:
      
        # Import settings here to avoid cyclic dependency
        from settings import AIAssistantSettings
        if AIAssistantSettings.instance().get("debug", 0):
            ida_kernwin.msg(f"[AI ASSISTANT DEBUG] {message}\n")
    except Exception:
        print(f"[AI ASSISTANT DEBUG] {message}")

def log_error(message: str):
    """Output error message (always shown)"""
    try:
        ida_kernwin.msg(f"[AI ASSISTANT ERROR] {message}\n")
    except Exception:
        print(f"[AI ASSISTANT ERROR] {message}")

def log_warning(message: str):
    """Output warning message (always shown)"""
    try:
        ida_kernwin.msg(f"[AI ASSISTANT WARNING] {message}\n")
    except Exception:
        print(f"[AI ASSISTANT WARNING] {message}")
