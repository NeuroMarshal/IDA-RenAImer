# ida_interface.py - Interface for interacting with IDA Pro

import re
from typing import Dict, Optional

import idaapi
import ida_kernwin
import ida_hexrays
import ida_funcs
import ida_name
import ida_lines
import ida_xref
import idautils
import textwrap
try:
    import ida_struct
    IDA_STRUCT_AVAILABLE = True
except ImportError:
    IDA_STRUCT_AVAILABLE = False

from settings import AIAssistantSettings
from logger import log_info, log_debug, log_error, log_warning

class IDAInterface:
    """Class for interacting with the IDA Pro API"""
    
    def __init__(self):
        pass
    
    def validate_name(self, name: str) -> str:
        """Validate a variable/function name for IDA"""
        if not name:
            return "unnamed"
        
        # remove invalid characters, keep only letters, digits and _
        clean_name = re.sub(r'[^a-zA-Z0-9_]', '_', name)
        
        # name cannot start with a digit
        if clean_name and clean_name[0].isdigit():
            clean_name = f"var_{clean_name}"
        
        # minimal length
        if len(clean_name) < 2:
            clean_name = f"var_{clean_name}"
            
        return clean_name
    
    def format_comment(self, comment: str, max_len: int) -> str:
        """Wrap lines by max_len processing only \n (no extra replacements)."""
        wrapped_parts = [
            textwrap.fill(
                part,
                width=max_len,
                break_long_words=False,   # do not split long identifiers
                replace_whitespace=False  # preserve extra spaces
            )
            for part in comment.splitlines()  # split by existing \n
        ]

        return "\n".join(wrapped_parts)
    
    def get_current_function(self) -> Optional[ida_hexrays.cfunc_t]:
        """Get the current function in the decompiler"""
        try:
            return ida_hexrays.decompile(idaapi.get_screen_ea())
        except ida_hexrays.DecompilationFailure:
            return None

    def get_function_stats(self, cfunc: ida_hexrays.cfunc_t) -> Dict[str, int]:
        """Count variables, function calls and structures in a function"""
        vars_list = getattr(cfunc, "lvars", [])

        def _is_arg_var(v) -> bool:
            """Return True if the variable is a function argument."""
            attr = getattr(v, "is_arg_var", None)
            try:
                if callable(attr):
                    return bool(attr())
                return bool(attr)
            except Exception:
                return False

        var_count = sum(1 for v in vars_list if not _is_arg_var(v))

        func_set = set()
        for ea in idautils.FuncItems(cfunc.entry_ea):
            for target in idautils.CodeRefsFrom(ea, False):
                func = ida_funcs.get_func(target)
                if func:
                    func_set.add(func.start_ea)

        struct_names = set(re.findall(r"struct\s+(\w+)", str(cfunc)))

        return {
            "variables": var_count,
            "functions": len(func_set),
            "structures": len(struct_names),
        }
    # may be useful for something, currently unused
    def get_selection(self, viewer) -> Optional[str]:
        """Get selected pseudocode text"""
        p0, p1 = ida_kernwin.twinpos_t(), ida_kernwin.twinpos_t()
        if not ida_kernwin.read_selection(viewer, p0, p1):
            return None
        
        user_data = ida_kernwin.get_viewer_user_data(viewer)
        line_array = ida_kernwin.linearray_t(user_data)
        line_array.set_place(p0.at)
        
        output_lines = []
        while True:
            place = line_array.get_place()
            if ida_kernwin.l_compare2(place, p1.at, user_data) > 0:
                break
            
            line = ida_lines.tag_remove(line_array.down())
            
            if ida_kernwin.l_compare2(place, p0.at, user_data) == 0:
                line = line[p0.x:]
            if ida_kernwin.l_compare2(place, p1.at, user_data) == 0:
                line = line[:p1.x]
            
            output_lines.append(line)
        
        return "\\n".join(output_lines)
    
    def get_function_context(self, ea: int) -> Dict:
        """Get function context (called and calling functions)"""
        seen_functions = {ea}
        code_snippets = []
        called_count = calling_count = 0
        
        max_called = AIAssistantSettings.instance().get("max_called_functions", 8)
        max_calling = AIAssistantSettings.instance().get("max_calling_functions", 4)
        
        def add_function_snippet(func_ea: int, tag: str):
            nonlocal code_snippets
            try:
                cfunc = ida_hexrays.decompile(func_ea)
                code_text = str(cfunc)
            except ida_hexrays.DecompilationFailure:
                return
            
            func_name = ida_funcs.get_func_name(func_ea)
            code_snippets.append(f"// {tag}: {func_name}\\n{code_text}\\n")
            seen_functions.add(func_ea)
        
        # Add main function (disabled to avoid repeating analyzed code)
        #add_function_snippet(ea, "MAIN FUNCTION")
        
        # Add called functions
        for addr in idautils.FuncItems(ea):
            if called_count >= max_called:
                break
            
            for target in idautils.CodeRefsFrom(addr, False):
                if target in seen_functions:
                    continue
                
                func = ida_funcs.get_func(target)
                if func:
                    add_function_snippet(func.start_ea, "CALLED FUNCTION")
                    called_count += 1
                    if called_count >= max_called:
                        break
        
        # Add calling functions via CodeRefsTo to find ALL call sites
        for cref_ea in idautils.CodeRefsTo(ea, False):
            if calling_count >= max_calling:
                break
            func = ida_funcs.get_func(cref_ea)
            if not func:
                continue
            # take the caller function start to avoid duplicates
            caller_start = func.start_ea
            if caller_start in seen_functions:
                continue
            add_function_snippet(caller_start, "CALLING FUNCTION")
            calling_count += 1
        
        if AIAssistantSettings.instance().get("debug", 0):
            log_debug(f"Function context: called={called_count}, calling={calling_count}")
        
        return {
            "text": "".join(code_snippets),
            "called": called_count,
            "calling": calling_count
        }
    
    def apply_analysis_results(self, cfunc: ida_hexrays.cfunc_t, analysis_data: dict):
        """Apply analysis results to a function in IDA"""
        func = ida_funcs.get_func(cfunc.entry_ea)
        if not func:
            log_warning("Failed to get function")
            return
        
        debug = AIAssistantSettings.instance().get("debug", 0)
        
        # apply comment
        if comment := analysis_data.get("comment"):
            max_len = AIAssistantSettings.instance().get("comment_max_line_length", 128)
            formatted_comment = self.format_comment(comment, max_len)
            ida_funcs.set_func_cmt(func, formatted_comment, True)
        
        # ─── rename the analyzed function itself (entry point) ───
        entry = analysis_data.get("entrypoint")          # now an object-dict
        if isinstance(entry, dict):
            new_name = entry.get("new_name")             # take new name
            if new_name:
                clean_name = self.validate_name(new_name)

                if clean_name != new_name and debug:
                    log_debug(f"Function name corrected: {new_name} -> {clean_name}")

                flags = ida_name.SN_AUTO | ida_name.SN_NOWARN | ida_name.SN_FORCE
                success = ida_name.set_name(func.start_ea, clean_name, flags)

                if not success and debug:
                    log_warning(f"Failed to rename function to {clean_name}")
        else:
            if debug:
                log_warning("'entrypoint' field missing or has wrong format")


        # Rename variables
        var_count = 0
        failed_vars = []
        for var_data in analysis_data.get("variables", []):
            try:
                clean_name = self.validate_name(var_data["new_name"])
                if clean_name != var_data["new_name"] and debug:
                    log_debug(f"Variable name corrected: {var_data['new_name']} -> {clean_name}")
                
                success = ida_hexrays.rename_lvar(func.start_ea, var_data["original_name"], clean_name)
                if success:
                    var_count += 1
                else:
                    failed_vars.append(var_data["original_name"])
                    if debug:
                        log_debug(f"Failed to rename variable {var_data['original_name']}")
            except Exception as e:
                failed_vars.append(var_data["original_name"])
                if debug:
                    log_debug(f"Variable rename error {var_data['original_name']}: {e}")
        
        if failed_vars and debug:
            log_warning(f"Failed to rename variables: {', '.join(failed_vars)}")
        
        # Rename called functions
        func_count = 0
        failed_funcs = []
        if AIAssistantSettings.instance().get("rename_called_functions", True):
            for func_data in analysis_data.get("functions", []):
                clean_name = self.validate_name(func_data["new_name"])
                if clean_name != func_data["new_name"] and debug:
                    log_debug(f"Function name corrected: {func_data['new_name']} -> {clean_name}")
                
                # search function by name and rename
                for func_ea in idautils.Functions():
                    if ida_name.get_name(func_ea) == func_data["original_name"]:
                        try:
                            flags = ida_name.SN_AUTO | ida_name.SN_NOWARN | ida_name.SN_FORCE
                            success = ida_name.set_name(func_ea, clean_name, flags)
                            if success:
                                func_count += 1
                            else:
                                failed_funcs.append(func_data["original_name"])
                        except Exception as e:
                            failed_funcs.append(func_data["original_name"])
                            if debug:
                                log_debug(f"Function rename error {func_data['original_name']}: {e}")
                        break
        
        if failed_funcs and debug:
            log_warning(f"Failed to rename functions: {', '.join(failed_funcs)}")
        
        # Rename structures
        struct_count = 0
        failed_structs = []
        if AIAssistantSettings.instance().get("rename_structs", True):
            for struct_data in analysis_data.get("structures", []):
                try:
                    clean_name = self.validate_name(struct_data["new_name"])
                    original_name = struct_data["original_name"]
                    
                    if IDA_STRUCT_AVAILABLE:
                        # use ida_struct API
                        struc_id = ida_struct.get_struc_id(original_name)
                        if struc_id != idaapi.BADADDR:
                            success = ida_struct.set_struc_name(struc_id, clean_name)
                            if success:
                                struct_count += 1
                            else:
                                failed_structs.append(original_name)
                        else:
                            failed_structs.append(original_name)
                    else:
                        # use idc API
                        import idc
                        struc_id = idc.get_struc_id(original_name)
                        if struc_id != idc.BADADDR:
                            success = idc.set_struc_name(struc_id, clean_name)
                            if success:
                                struct_count += 1
                            else:
                                failed_structs.append(original_name)
                        else:
                            failed_structs.append(original_name)
                            
                except Exception as e:
                    failed_structs.append(struct_data.get("original_name", "unknown"))
                    if debug:
                        log_debug(f"Structure rename error: {e}")
        
        if failed_structs and debug:
            log_warning(f"Failed to rename structures: {', '.join(failed_structs)}")
        
        # refresh the view
        cfunc.refresh_func_ctext()
        
        # display final statistics
        total_vars = len(analysis_data.get("variables", []))
        total_funcs = len(analysis_data.get("functions", []))
        total_structs = len(analysis_data.get("structures", []))

        msg = (
            f"Renamed: "
            f"variables {var_count}/{total_vars}, "
            f"functions {func_count}/{total_funcs}, "
            f"structures {struct_count}/{total_structs}"
        )
        log_info(msg)
