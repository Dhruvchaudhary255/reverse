#!/usr/bin/env python3
"""
IDA Library Analyzer for XXTEA samples
Analyzes binaries to find entry points and XXTEA setters
"""

import sys
import os
import subprocess
from pathlib import Path
from datetime import datetime
import argparse
import re

# Import idapro
import idapro

# Centralized XXTEA-related keywords for detection
XXTEA_KEYWORDS = {
    'functions': ['setXXTeaKey', 'setXXTEAKey', 'addXXTeaKey', 'jsb_set_xxtea_key', 'regist_lua'],
    'classes': ['ResourcesDecode', 'LuaStack'],
    'key_indicators': ['strcpy', 'addXXTeaKey', 'setXXTEAKey', '"']  # For identifying key setup lines
}

def is_xxtea_related(text):
    """Check if text contains XXTEA-related keywords"""
    for keyword in XXTEA_KEYWORDS['functions']:
        if keyword in text:
            return True
    for keyword in XXTEA_KEYWORDS['classes']:
        if keyword in text:
            return True
    return False

def is_key_setup_line(line):
    """Check if a line contains key setup indicators"""
    return any(kw in line for kw in XXTEA_KEYWORDS['key_indicators'])

# Disable console messages for cleaner output
idapro.enable_console_messages(False)

def get_dynamic_symbols(binary_path):
    """Get dynamic symbols using nm -D"""
    try:
        result = subprocess.run(['nm', '-D', binary_path], 
                              capture_output=True, text=True, check=False)
        symbols = []
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[1] == 'T':
                addr = int(parts[0], 16)
                name = parts[2]
                symbols.append((addr, name))
        return symbols
    except:
        return []

def is_entry_point(name, demangled=None):
    """Check if symbol is an entry point"""
    lower_name = name.lower()
    lower_demangled = demangled.lower() if demangled else lower_name
    
    if "cocos_android_app_init" in name:
        return True
    if "didfinishlaunching" in lower_name:
        return True
    if demangled and demangled != name and "didfinishlaunching" in lower_demangled:
        return True
    # BaseGame::init pattern - check both demangled and mangled forms
    if demangled and "BaseGame::init" in demangled:
        return True
    # Also check mangled form directly
    if "_ZN2cc8BaseGame4initEv" in name:
        return True
    # Game::init pattern
    if demangled and "Game::init" in demangled:
        return True
    # Also check mangled form for Game::init
    if "_ZN4Game4initEv" in name:
        return True
    # cocos_main pattern  
    if "cocos_main" in name:
        return True
    return False

def is_setter(name):
    """Check if symbol is a setter"""
    lower_name = name.lower()
    has_action = ("set" in lower_name or "add" in lower_name or "edit" in lower_name)
    has_target = ("cryptokey" in lower_name or "xxtea" in lower_name)
    return has_action and has_target

def analyze_binary(binary_path, decompile=True, clean_db=False, auto_wait=False, auto_retry=True):
    """Analyze a single binary
    
    Args:
        binary_path: Path to the binary to analyze
        decompile: Whether to decompile functions
        clean_db: Whether to clean existing IDA database files (default: False to reuse)
        auto_wait: Whether to wait for full IDA auto-analysis (slower but more thorough)
        auto_retry: Whether to automatically retry with auto_wait if no setter xrefs found
    """
    result = {
        'name': Path(binary_path).name,
        'hash': Path(binary_path).stem.split('-')[-1] if '-' in Path(binary_path).stem else Path(binary_path).stem,
        'entry_points': [],
        'setters': [],
        'error': None
    }
    
    # Get dynamic symbols
    print(f"  Getting dynamic symbols...")
    dyn_symbols = get_dynamic_symbols(binary_path)
    
    # Find entry points and setters
    entry_points = []
    setters = []
    
    for addr, name in dyn_symbols:
        if is_entry_point(name):
            entry_points.append((addr, name))
        if is_setter(name):
            setters.append((addr, name))
    
    if not setters and not entry_points:
        result['error'] = "No entry points or XXTEA setters found"
        return result
    
    print(f"  Found {len(entry_points)} entry points, {len(setters)} setters")
    
    # Open in IDA
    binary_path = os.path.abspath(binary_path)
    
    # Clean up old database files if requested
    if clean_db:
        for ext in ['.i64', '.id0', '.id1', '.id2', '.nam', '.til']:
            db_file = binary_path + ext
            if os.path.exists(db_file):
                os.remove(db_file)
        print("  Cleaned existing IDA database files")
    else:
        # Check if database exists
        if os.path.exists(binary_path + '.id0'):
            print("  Reusing existing IDA database")
    
    print(f"  Opening in IDA with compression...")
    # Pass -P+ flag to enable database compression in IDA 9.1+
    ida_result = idapro.open_database(binary_path, False, "-P+")
    
    if ida_result != 0:
        result['error'] = f"Failed to open in IDA: error {ida_result}"
        return result
    
    # Import IDA modules
    import ida_auto
    import ida_funcs
    import ida_name
    import idautils
    import idc
    
    # Create functions for ALL dynamic symbols to ensure xrefs are found
    for addr, name in dyn_symbols:
        ida_funcs.add_func(addr)
    
    # Run full auto-analysis if requested (slower but more thorough)
    if auto_wait:
        print("  Running full auto-analysis (this may take a while)...")
        import time
        start_time = time.time()
        ida_auto.auto_wait()
        elapsed = time.time() - start_time
        print(f"  Auto-analysis complete (took {elapsed:.1f} seconds)")
    
    # Import decompiler if requested
    if decompile:
        try:
            import ida_hexrays
            has_decompiler = ida_hexrays.init_hexrays_plugin()
        except:
            has_decompiler = False
    else:
        has_decompiler = False
    
    # Analyze entry points
    for addr, mangled_name in entry_points:
        entry_info = {
            'address': f"0x{addr:x}",
            'mangled': mangled_name,
            'demangled': None,
            'xrefs': 0,
            'instructions': [],
            'decompiled': None
        }
        
        # Demangle
        demangled = ida_name.demangle_name(mangled_name, ida_name.DQT_FULL)
        if demangled:
            entry_info['demangled'] = demangled
        
        # Get or create function
        ida_funcs.add_func(addr)  # Try to create if doesn't exist
        func = ida_funcs.get_func(addr)
        if func:
                entry_info['size'] = func.end_ea - func.start_ea
                
                # Check xrefs
                xrefs = list(idautils.XrefsTo(addr))
                entry_info['xrefs'] = len(xrefs)
                
                # Get all instructions
                ea = func.start_ea
                while ea < func.end_ea:
                    
                    mnem = idc.print_insn_mnem(ea)
                    if mnem:
                        ops = []
                        for j in range(3):
                            op = idc.print_operand(ea, j)
                            if op:
                                ops.append(op)
                        
                        inst_str = f"0x{ea:x}: {mnem:6} {', '.join(ops)}"
                        entry_info['instructions'].append(inst_str)
                        
                        # Check for interesting calls
                        if mnem == "BL":
                            target = idc.get_operand_value(ea, 0)
                            if target and target != -1:
                                target_name = ida_funcs.get_func_name(target)
                                if target_name and ("xxtea" in target_name.lower() or "crypto" in target_name.lower()):
                                    entry_info['instructions'].append(f"         -> Calls {target_name}")
                    
                    ea = idc.next_head(ea)
                
                # Try to decompile
                if has_decompiler and decompile:
                    try:
                        cfunc = ida_hexrays.decompile(func.start_ea)
                        if cfunc:
                            entry_info['decompiled'] = str(cfunc)
                    except:
                        pass
        
        result['entry_points'].append(entry_info)
    
    # Analyze setters
    for addr, mangled_name in setters:
        setter_info = {
            'address': f"0x{addr:x}",
            'mangled': mangled_name,
            'demangled': None,
            'xrefs': 0,
            'direct_xrefs': [],  # All direct xrefs
            'xref_from': [],  # Call chains
            'global_ref': None,
            'instructions': []
        }
        
        # Demangle
        demangled = ida_name.demangle_name(mangled_name, ida_name.DQT_FULL)
        if demangled:
            setter_info['demangled'] = demangled
        
        # Get or create function
        ida_funcs.add_func(addr)  # Try to create if doesn't exist
        func = ida_funcs.get_func(addr)
        if func:
                setter_info['size'] = func.end_ea - func.start_ea
                
                # Get all direct xrefs first
                xrefs = list(idautils.XrefsTo(addr))
                setter_info['xrefs'] = len(xrefs)
                
                # Store detailed info for each direct xref
                for xref in xrefs:
                    xref_info = {
                        'call_site': f"0x{xref.frm:x}",
                        'type': xref.type
                    }
                    
                    # Try to get function info if xref is from code
                    calling_func = ida_funcs.get_func(xref.frm)
                    if calling_func:
                        caller_name = ida_funcs.get_func_name(calling_func.start_ea)
                        if caller_name:
                            demangled = ida_name.demangle_name(caller_name, ida_name.DQT_FULL)
                            xref_info.update({
                                'address': f"0x{calling_func.start_ea:x}",
                                'function': caller_name,
                                'demangled': demangled if demangled else caller_name
                            })
                    else:
                        # Xref is from data or non-function area
                        name = ida_name.get_name(xref.frm)
                        seg = idc.get_segm_name(xref.frm)
                        
                        # Check if it's in a vtable
                        containing_name = None
                        # Look for vtable or other structure this might be part of
                        for offset in [0, 8, 16, 24, 32, 40, 48, 56, 64]:  # Check nearby for vtable start
                            check_addr = xref.frm - offset
                            check_name = ida_name.get_name(check_addr)
                            if check_name and ('vtable' in check_name.lower() or 'vftable' in check_name.lower() or '_ZTV' in check_name):
                                containing_name = check_name
                                break
                        
                        if name:
                            desc = name
                        elif containing_name:
                            desc = f"vtable entry in {containing_name}"
                        elif seg:
                            desc = f"data reference in {seg} section"
                        else:
                            desc = f"data reference at 0x{xref.frm:x}"
                        
                        # Check who references this data location
                        data_users = []
                        data_xrefs = list(idautils.XrefsTo(xref.frm))
                        for data_xref in data_xrefs[:5]:  # Limit to 5 to avoid too much output
                            user_func = ida_funcs.get_func(data_xref.frm)
                            if user_func:
                                user_name = ida_funcs.get_func_name(user_func.start_ea)
                                if user_name:
                                    demangled_user = ida_name.demangle_name(user_name, ida_name.DQT_FULL)
                                    data_users.append({
                                        'function': demangled_user if demangled_user else user_name,
                                        'address': f"0x{user_func.start_ea:x}"
                                    })
                            
                        xref_info.update({
                            'address': f"0x{xref.frm:x}",
                            'function': name if name else f"data_ref_{xref.frm:x}",
                            'demangled': desc,
                            'segment': seg if seg else 'unknown',
                            'used_by': data_users if data_users else None
                        })
                    
                    setter_info['direct_xrefs'].append(xref_info)
                
                # Get calling functions with recursive backtrace and decompilation
                def trace_callers(target_addr, depth=0, max_depth=5, visited=None):
                    """Recursively trace who calls this function, decompiling each"""
                    if visited is None:
                        visited = set()
                    if depth >= max_depth or target_addr in visited:
                        return []
                    visited.add(target_addr)
                    
                    callers = []
                    xrefs_to_target = list(idautils.XrefsTo(target_addr))
                    
                    # Process ALL xrefs instead of limiting
                    for xref in xrefs_to_target:
                        calling_func = ida_funcs.get_func(xref.frm)
                        if calling_func:
                            caller_name = ida_funcs.get_func_name(calling_func.start_ea)
                            if caller_name:
                                caller_info = {
                                    'address': f"0x{calling_func.start_ea:x}",
                                    'call_site': f"0x{xref.frm:x}",
                                    'function': caller_name,
                                    'demangled': ida_name.demangle_name(caller_name, ida_name.DQT_FULL),
                                    'type': xref.type,
                                    'depth': depth,
                                    'is_entry_point': is_entry_point(caller_name, ida_name.demangle_name(caller_name, ida_name.DQT_FULL))
                                }
                                
                                # Get assembly for context around call site
                                asm_lines = []
                                ea = xref.frm - 0x10  # Start 4 instructions before
                                for _ in range(8):  # Show 8 instructions total
                                    if ea >= calling_func.start_ea and ea < calling_func.end_ea:
                                        mnem = idc.print_insn_mnem(ea)
                                        if mnem:
                                            ops = []
                                            for j in range(3):
                                                op = idc.print_operand(ea, j)
                                                if op:
                                                    ops.append(op)
                                            marker = ">>> " if ea == xref.frm else "    "
                                            asm_lines.append(f"{marker}0x{ea:x}: {mnem:6} {', '.join(ops)}")
                                    ea = idc.next_head(ea)
                                caller_info['asm_context'] = asm_lines
                                
                                # Decompile the caller if requested
                                if decompile:
                                    try:
                                        cfunc = ida_hexrays.decompile(calling_func.start_ea)
                                        if cfunc:
                                            caller_info['decompiled'] = str(cfunc)
                                    except:
                                        pass
                                
                                # Continue tracing if not an entry point
                                if not caller_info['is_entry_point']:
                                    parent_callers = trace_callers(calling_func.start_ea, depth + 1, max_depth, visited)
                                    if parent_callers:
                                        caller_info['callers'] = parent_callers
                                callers.append(caller_info)
                    return callers
                
                # Trace call chains backward from setter
                setter_info['xref_from'] = trace_callers(addr)
                
                # Get all instructions and look for patterns
                ea = func.start_ea
                while ea < func.end_ea:
                    
                    mnem = idc.print_insn_mnem(ea)
                    if mnem:
                        ops = []
                        for j in range(3):
                            op = idc.print_operand(ea, j)
                            if op:
                                ops.append(op)
                        
                        inst_str = f"0x{ea:x}: {mnem:6} {', '.join(ops)}"
                        setter_info['instructions'].append(inst_str)
                        
                        # Check for global references
                        if mnem in ["ADRL", "ADRP"] and not setter_info['global_ref']:
                            target = idc.get_operand_value(ea, 1)
                            if target > 0x1000000:
                                setter_info['global_ref'] = f"0x{target:x}"
                    
                    ea = idc.next_head(ea)
        
        result['setters'].append(setter_info)
    
    # Close database (save=True to preserve the database for reuse)
    idapro.close_database(True)
    
    # Check if we should retry with auto_wait
    if auto_retry and not auto_wait and result['setters']:
        # Check if any setter has xrefs
        has_setter_xrefs = any(setter['xrefs'] > 0 for setter in result['setters'])
        if not has_setter_xrefs:
            print("  No setter xrefs found, retrying with auto_wait (this may take a while)...")
            print("  Cleaning database and retrying with full analysis...")
            # Retry with auto_wait enabled
            return analyze_binary(binary_path, decompile, clean_db=True, auto_wait=True, auto_retry=False)
    
    return result

def generate_report(result, output_path):
    """Generate markdown report for a sample"""
    # If output_path is a directory, use library-based naming with hash suffix to avoid collisions
    # If it's a file path, use it directly
    if output_path.is_dir():
        # Extract library name from the full filename (e.g., libcocos2dlua-HASH.so -> libcocos2dlua-HASH.md)
        name = result['name']
        if name.endswith('.so'):
            name = name[:-3]  # Remove .so extension
        # Keep the full name including hash to avoid collisions
        filename = f"{name}.md"
        filepath = output_path / filename
    else:
        filepath = output_path
    
    with open(filepath, 'w') as f:
        # Header - include hash for easy copy-paste
        f.write(f"# Analysis Report: {result['name']}\n\n")
        f.write(f"**Hash:** `{result['hash']}`\n\n")
        
        if result['error']:
            f.write(f"## Error\n\n")
            f.write(f"{result['error']}\n")
            return
        
        # Overview
        f.write("## Overview\n\n")
        f.write(f"This binary has {len(result['entry_points'])} entry points and {len(result['setters'])} XXTEA setter functions.\n\n")
        
        # List setters
        if result['setters']:
            f.write("### XXTEA Setters\n\n")
            for i, setter in enumerate(result['setters'], 1):
                name = setter['demangled'] or setter['mangled']
                f.write(f"{i}. `{name}`\n")
                f.write(f"   - {setter['xrefs']} xrefs\n")
                if setter['global_ref']:
                    f.write(f"   - Stores key at address `{setter['global_ref']}`\n")
            f.write("\n")
        
        # List entry points
        if result['entry_points']:
            f.write("### Entry Points\n\n")
            for i, entry in enumerate(result['entry_points'], 1):
                name = entry['demangled'] or entry['mangled']
                f.write(f"{i}. `{name}`\n")
            f.write("\n")
        
        
        # Detailed Entry Points Analysis
        if result['entry_points']:
            f.write("## Entry Point Details\n\n")
            
            for i, entry in enumerate(result['entry_points'], 1):
                name = entry['demangled'] or entry['mangled']
                f.write(f"### Entry Point {i}: {name}\n\n")
                
                f.write("```\n")
                f.write(f"Address: {entry['address']}\n")
                if 'size' in entry:
                    f.write(f"Size: {entry['size']} bytes\n")
                f.write(f"Xrefs: {entry['xrefs']}\n")
                f.write("```\n\n")
                
                if entry.get('decompiled'):
                    f.write("**Decompiled Code:**\n```cpp\n")
                    lines = entry['decompiled'].split('\n')
                    setter_calls = []
                    
                    for line in lines:
                        f.write(f"{line}\n")
                        # Check for calls to setter functions
                        if is_xxtea_related(line):
                            setter_calls.append(line.strip())
                    
                    f.write("```\n")
                    
                    if setter_calls:
                        f.write(f"\n**Key function calls found:** {len(setter_calls)} call(s)\n")
                        for call in setter_calls:  # Show all calls, not just first 3
                            f.write(f"- `{call}`\n")
                    f.write("\n")
                
                # Always show disassembly if available
                if entry['instructions']:
                    f.write("**Disassembly:**\n```armasm\n")
                    for inst in entry['instructions']:  # Show all instructions
                        f.write(f"{inst}\n")
                    f.write("```\n\n")
                elif not entry.get('decompiled'):
                    f.write("**No decompilation or disassembly available.**\n\n")
        
        # Detailed Setter Analysis
        if result['setters']:
            f.write("## Setter Details\n\n")
            
            for i, setter in enumerate(result['setters'], 1):
                name = setter['demangled'] or setter['mangled']
                f.write(f"### Setter {i}: {name}\n\n")
                
                f.write(f"**Address:** `{setter['address']}`\n")
                if 'size' in setter:
                    f.write(f"**Size:** {setter['size']} bytes\n")
                f.write(f"**Cross-references:** {setter['xrefs']}\n\n")
                
                # Show all direct xrefs
                if setter.get('direct_xrefs'):
                    f.write("#### All Direct Cross-References\n\n")
                    for j, xref in enumerate(setter['direct_xrefs'], 1):
                        f.write(f"{j}. `{xref['demangled']}` at `{xref['address']}`\n")
                        f.write(f"   - Call site: `{xref.get('call_site', xref['address'])}`\n")
                        if xref.get('used_by'):
                            f.write(f"   - **This vtable/data is referenced by:**\n")
                            for user in xref['used_by']:
                                f.write(f"     - `{user['function']}` at `{user['address']}`\n")
                    f.write("\n")
                
                if setter['global_ref']:
                    f.write(f"**Key storage location:** `{setter['global_ref']}`\n")
                
                if setter['xref_from']:
                    f.write("\n#### Call Chains\n\n")
                    
                    # Build linear call chains
                    def build_linear_chains(chain, current_path=[]):
                        """Build linear call chains from nested structure"""
                        func_name = chain.get('demangled') or chain.get('function', 'Unknown')
                        if len(func_name) > 60:
                            func_name = func_name[:57] + "..."
                        
                        chain_info = {
                            'name': func_name,
                            'address': chain['address'],
                            'is_entry': chain.get('is_entry_point', False),
                            'decompiled': chain.get('decompiled'),
                            'asm_context': chain.get('asm_context')
                        }
                        
                        new_path = current_path + [chain_info]
                        
                        if chain.get('is_entry_point') or 'callers' not in chain:
                            # End of chain
                            return [new_path]
                        
                        all_paths = []
                        for caller in chain.get('callers', []):
                            all_paths.extend(build_linear_chains(caller, new_path))
                        return all_paths
                    
                    # Collect all call chains
                    all_chains = []
                    for xref in setter['xref_from'][:3]:
                        all_chains.extend(build_linear_chains(xref))
                    
                    # Display each chain linearly
                    for i, chain in enumerate(all_chains, 1):
                        f.write(f"**Chain {i}:**\n\n")
                        
                        # Show the chain as a simple arrow flow
                        chain_str = " → ".join([c['name'] + (" [ENTRY]" if c['is_entry'] else "") for c in reversed(chain)])
                        f.write(f"`{chain_str}`\n\n")
                        
                        # Find and show the most relevant function with actual code
                        key_func = None
                        for func in chain:
                            if func['decompiled']:
                                # Check if this function actually contains key setup
                                code = func['decompiled']
                                if is_xxtea_related(code):
                                    # This is the actual function with key setup, not a thunk
                                    if 'thunk' not in code:
                                        key_func = func
                                        break
                        
                        if key_func:
                            f.write(f"\n**Key function: {key_func['name']}** at `{key_func['address']}`\n\n")
                            # Extract key lines from the decompiled code
                            key_lines = []
                            all_lines = key_func['decompiled'].split('\n')
                            for i, line in enumerate(all_lines):
                                # Look for lines with string literals that might be keys
                                if is_key_setup_line(line):
                                    # Get context around key lines
                                    start = max(0, i - 2)
                                    end = min(len(all_lines), i + 3)
                                    for j in range(start, end):
                                        if all_lines[j] not in key_lines:
                                            key_lines.append(all_lines[j])
                            
                            if key_lines:
                                f.write("**XXTEA Key Setup Code:**\n```cpp\n")
                                for line in key_lines:
                                    f.write(f"{line}\n")
                                f.write("```\n\n")
                            
                            # Put full code in collapsible section
                            f.write("<details>\n")
                            f.write("<summary>Full decompiled function</summary>\n\n")
                            f.write("```cpp\n")
                            f.write(key_func['decompiled'])
                            f.write("```\n")
                            f.write("</details>\n")
                        
                        f.write("---\n\n")
                
                f.write("\n")
        

def decompile_target_function(binary_path, target_func, output_path=None):
    """Decompile a specific function from a binary
    
    Args:
        binary_path: Path to the binary file
        target_func: Function name to decompile (e.g., sub_B8DB98)
        output_path: Output path for the decompiled code
    
    Returns:
        Path to the output file if successful, None otherwise
    """
    import hashlib
    
    # Calculate hash for the binary
    with open(binary_path, 'rb') as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()
    
    # Generate output filename
    if output_path:
        output_file = Path(output_path)
    else:
        # Default output: libname-hash-TARGET.md
        base_name = Path(binary_path).stem
        # Check if base_name already contains the hash
        if file_hash in base_name:
            # Hash is already in filename, don't add it again
            output_file = Path(binary_path).parent / f"{base_name}-{target_func.upper()}.md"
        else:
            # Add hash if not present
            output_file = Path(binary_path).parent / f"{base_name}-{file_hash}-{target_func.upper()}.md"
    
    print(f"Decompiling function {target_func} from {binary_path}")
    print(f"Output will be saved to: {output_file}")
    
    # Open in IDA
    print("Opening in IDA...")
    ida_result = idapro.open_database(str(binary_path), False, "-P+")
    if ida_result != 0:
        print(f"Failed to open in IDA: error {ida_result}")
        return None
    
    # Import IDA modules
    import ida_auto
    import ida_funcs
    import ida_name
    import idautils
    import idc
    import ida_hexrays
    
    # Run auto-analysis
    print("Running auto-analysis...")
    ida_auto.auto_wait()
    
    # Find the target function
    target_addr = None
    
    # Try to find by name first
    target_addr = ida_name.get_name_ea(0, target_func)
    
    if target_addr == idc.BADADDR:
        # Try with case variations
        for variant in [target_func.lower(), target_func.upper(), f"_{target_func}"]:
            target_addr = ida_name.get_name_ea(0, variant)
            if target_addr != idc.BADADDR:
                break
    
    if target_addr == idc.BADADDR:
        # Try to parse as hex address
        try:
            if target_func.startswith("0x"):
                target_addr = int(target_func, 16)
            elif target_func.startswith("sub_"):
                # Extract hex from sub_XXXXXX format
                hex_part = target_func[4:]
                target_addr = int(hex_part, 16)
            else:
                target_addr = int(target_func, 16)
        except:
            pass
    
    if target_addr == idc.BADADDR or target_addr is None:
        print(f"Error: Could not find function {target_func}")
        idapro.close_database(True)
        return None
    
    print(f"Found function at 0x{target_addr:x}")
    
    # Get or create function at address
    ida_funcs.add_func(target_addr)
    func = ida_funcs.get_func(target_addr)
    
    if not func:
        print(f"Error: No function at address 0x{target_addr:x}")
        idapro.close_database(True)
        return None
    
    # Try to decompile
    decompiled = None
    try:
        if ida_hexrays.init_hexrays_plugin():
            cfunc = ida_hexrays.decompile(target_addr)
            if cfunc:
                decompiled = str(cfunc)
                print(f"Successfully decompiled function (size: {len(decompiled)} chars)")
    except Exception as e:
        print(f"Decompilation failed: {e}")
    
    # Write output
    with open(output_file, 'w') as f:
        f.write(f"# Decompilation of {target_func}\n\n")
        f.write(f"**Binary:** `{binary_path.name}`\n")
        f.write(f"**SHA256:** `{file_hash}`\n")
        f.write(f"**Function:** `{target_func}` at `0x{target_addr:x}`\n")
        f.write(f"**Size:** {func.end_ea - func.start_ea} bytes\n\n")
        
        if decompiled:
            f.write("## Decompiled Code\n\n")
            f.write("```cpp\n")
            f.write(decompiled)
            f.write("\n```\n")
        else:
            f.write("## Assembly (Decompilation not available)\n\n")
            f.write("```asm\n")
            ea = func.start_ea
            while ea < func.end_ea:
                mnem = idc.print_insn_mnem(ea)
                if mnem:
                    ops = []
                    for j in range(3):
                        op = idc.print_operand(ea, j)
                        if op:
                            ops.append(op)
                    f.write(f"0x{ea:08x}: {mnem:8} {', '.join(ops)}\n")
                ea = idc.next_head(ea)
            f.write("```\n")
    
    # Close database
    idapro.close_database(True)
    
    return output_file

def main():
    parser = argparse.ArgumentParser(description='Analyze binaries for XXTEA using idalib')
    parser.add_argument('target', help='Binary file or directory to analyze')
    parser.add_argument('-o', '--output', help='Output directory (default: same as source)')
    parser.add_argument('-d', '--decompile', action='store_true', default=True, help='Include decompiled code (requires Hex-Rays, default: True)')
    parser.add_argument('-c', '--clean', action='store_true', help='Clean existing IDA database files (default: reuse)')
    parser.add_argument('-a', '--auto-wait', action='store_true', help='Run full IDA auto-analysis (slower but more thorough)')
    parser.add_argument('--target-func', help='Decompile specific function (e.g., sub_B8DB98)')
    
    args = parser.parse_args()
    
    # Handle target function decompilation
    if args.target_func:
        # This is a specific function decompilation request
        binary_path = Path(args.target)
        if not binary_path.exists():
            print(f"Error: Binary {binary_path} not found")
            sys.exit(1)
        
        result = decompile_target_function(binary_path, args.target_func, args.output)
        if result:
            print(f"Function decompilation saved to: {result}")
        else:
            print("Error: Failed to decompile function")
            sys.exit(1)
        return
    
    target = Path(args.target)
    
    # Determine samples to analyze
    if target.is_file():
        samples = [target]
    elif target.is_dir():
        samples = list(target.glob("*.so"))
    else:
        print(f"ERROR: {target} not found")
        return
    
    if not samples:
        print("No .so files found")
        return
    
    print(f"Found {len(samples)} samples to analyze")
    
    # Determine output mode
    if args.output:
        output_dir = Path(args.output)
        output_dir.mkdir(exist_ok=True)
        use_same_dir = False
        print(f"Reports will be saved to: {output_dir}/")
    else:
        use_same_dir = True
        print("Reports will be saved alongside .so files")
    
    successful = 0
    
    for i, sample in enumerate(samples, 1):
        print(f"\n[{i}/{len(samples)}] {sample.name}")
        try:
            result = analyze_binary(str(sample), args.decompile, args.clean, args.auto_wait, auto_retry=True)
            
            # Print summary
            if result['error']:
                print(f"  ERROR: {result['error']}")
            else:
                if result['entry_points']:
                    print(f"  Entry points: {len(result['entry_points'])}")
                    for entry in result['entry_points']:
                        name = entry['demangled'] or entry['mangled']
                        if len(name) > 40:
                            name = name[:37] + "..."
                        print(f"    - {name}")
                
                if result['setters']:
                    print(f"  Setters: {len(result['setters'])}")
                    for setter in result['setters']:
                        name = setter['demangled'] or setter['mangled']
                        if len(name) > 40:
                            name = name[:37] + "..."
                        status = "no xrefs" if setter['xrefs'] == 0 else f"{setter['xrefs']} xrefs"
                        print(f"    - {name} ({status})")
                
                successful += 1
            
            # Generate report
            if use_same_dir:
                # Save alongside the .so file
                report_path = sample.with_suffix('.md')
                generate_report(result, report_path)
                print(f"  Report saved: {report_path.name}")
            else:
                generate_report(result, output_dir)
                print(f"  Report saved: {result['hash']}.md")
            
        except Exception as e:
            print(f"  EXCEPTION: {e}")
            # Create error report
            result = {
                'name': sample.name,
                'hash': sample.stem.split('-')[-1] if '-' in sample.stem else sample.stem,
                'entry_points': [],
                'setters': [],
                'error': str(e)
            }
            if use_same_dir:
                report_path = sample.with_suffix('.md')
                generate_report(result, report_path)
            else:
                generate_report(result, output_dir)
    
    # Create index only if using output directory
    if args.output:
        index_path = output_dir / "README.md"
        with open(index_path, 'w') as f:
            f.write("# IDA Analysis Reports\n\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"- Total samples: {len(samples)}\n")
            f.write(f"- Successfully analyzed: {successful}\n\n")
            f.write("## Reports\n\n")
            
            for sample in sorted(samples):
                hash_part = sample.stem.split('-')[-1] if '-' in sample.stem else sample.stem
                f.write(f"- [{sample.name}]({hash_part}.md)\n")
        
        print(f"\nAnalysis complete: {successful}/{len(samples)} successful")
        print(f"Reports saved to: {output_dir}/")
    else:
        print(f"\nAnalysis complete: {successful}/{len(samples)} successful")
        print("Reports saved alongside .so files")

if __name__ == "__main__":
    main()