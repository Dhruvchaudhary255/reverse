# IDA Library (idalib) Usage Guide

## Overview

idalib is IDA Pro's headless library interface introduced in IDA 9.0. It allows programmatic analysis of binaries without the GUI.

## Architecture

### Core Components

1. **idapro module** (`idapro/__init__.py`)
   - Main entry point for idalib
   - Loads native library (`libidalib.dylib` on macOS)
   - Provides core functions:
     - `open_database(file_name, run_auto_analysis, args, enable_history)`
     - `close_database(save)`
     - `enable_console_messages(enable)`
     - `get_library_version()`

2. **Configuration** (`idapro/config.py`)
   - Manages IDA installation directory
   - Config stored in `~/.idapro/ida-config.json`
   - Can override with `IDADIR` environment variable

3. **Native Library**
   - Located at: `/Applications/IDA Essential 9.2.app/Contents/MacOS/libidalib.dylib`
   - Must be initialized before use via `init_library()`
   - Single-threaded - all calls must be from same thread

### How idalib Works

1. **Initialization Flow**:
   ```python
   import idapro  # This loads libidalib.dylib and calls init_library()
   ```

2. **Database Opening**:
   ```python
   result = idapro.open_database("binary.so", True)
   # Returns:
   #   0 = success
   #   -1 = file not found
   #   1 = database format error
   #   2 = architecture not supported
   #   4 = database already exists/corrupted
   ```

3. **IDA Modules Loading**:
   - IDA modules (`ida_auto`, `ida_funcs`, etc.) can ONLY be imported AFTER a database is opened
   - They are dynamically loaded from the IDA installation directory
   - Located in: `/Applications/IDA Essential 9.2.app/Contents/MacOS/python/`

4. **Analysis Flow**:
   ```python
   # After database is open
   import ida_auto
   ida_auto.auto_wait()  # Wait for auto-analysis to complete
   ```

## Key Limitations

1. **Single Database**: Only one database can be open at a time
2. **Single Thread**: All operations must be from the same thread that initialized the library
3. **Module Import Order**: IDA modules can only be imported after opening a database
4. **Database Files**: Creates `.i64`, `.id0`, `.id1`, `.id2`, `.nam`, `.til` files alongside the binary
5. **Error Handling**: Limited error reporting - often just returns error codes

## Error Code Reference

| Code | Meaning |
|------|---------|
| 0 | Success |
| -1 | File not found or cannot be opened |
| 1 | Database format error |
| 2 | Architecture not supported |
| 4 | Database already exists or corrupted |

## Working Example

```python
#!/usr/bin/env python3
import idapro

# Enable debug output
idapro.enable_console_messages(True)

# Open database (creates .i64 files)
result = idapro.open_database("/path/to/binary.so", True)
if result != 0:
    print(f"Failed to open: error {result}")
    exit(1)

# NOW we can import IDA modules
import ida_auto
import ida_funcs
import ida_name
import idautils

# Wait for analysis
ida_auto.auto_wait()

# Do analysis
for func_ea in idautils.Functions():
    name = ida_funcs.get_func_name(func_ea)
    print(f"Function: {name} at 0x{func_ea:x}")

# Close database
idapro.close_database()
```

## Common Issues

### Issue 1: Module Import Errors
**Symptom**: `ModuleNotFoundError: No module named 'ida_auto'`
**Cause**: Trying to import IDA modules before opening a database
**Fix**: Only import IDA modules after successful `open_database()` call

### Issue 2: Database Corruption
**Symptom**: Error code 4, "Database already exists"
**Cause**: Previous analysis created `.i64` files that are corrupted
**Fix**: Delete all `.i64`, `.id0`, `.id1`, `.id2`, `.nam`, `.til` files

### Issue 3: Hanging Analysis
**Symptom**: Script hangs during `auto_wait()`
**Cause**: Large binary taking long time to analyze
**Fix**: 
- Use timeout mechanism
- Consider disabling auto-analysis: `open_database(file, False)`
- Manually trigger specific analysis passes

### Issue 4: No Functions Found
**Symptom**: `get_func_qty()` returns 0
**Cause**: Binary not properly analyzed or wrong architecture
**Fix**: 
- Ensure auto-analysis completes
- Check binary architecture matches IDA processor
- May need to manually create functions with `add_func()`

## Setup Requirements

1. **Install IDA**: IDA Pro or IDA Essential 9.0+
2. **Install idalib Python package**:
   ```bash
   pip install /Applications/IDA\ Essential\ 9.2.app/Contents/MacOS/idalib/python
   ```
3. **Activate idalib**:
   ```bash
   python /Applications/IDA\ Essential\ 9.2.app/Contents/MacOS/idalib/python/py-activate-idalib.py \
          -d /Applications/IDA\ Essential\ 9.2.app/Contents/MacOS
   ```

## Architecture-Specific Notes

### ARM64 Binaries
- IDA may not automatically detect all functions in stripped binaries
- May need to manually create functions at known addresses
- Use `ida_funcs.add_func(address)` to create functions

### Dynamic Symbols
- For stripped binaries, dynamic symbols (from `nm -D`) provide entry points
- These addresses can be used to manually create functions
- Example: `jsb_set_xxtea_key` at `0x1234ee0` in TODO samples

## Best Practices

1. **Always use absolute paths** for binary files
2. **Clean up database files** between runs to avoid corruption
3. **Enable console messages** for debugging: `idapro.enable_console_messages(True)`
4. **Check return codes** from `open_database()`
5. **Import IDA modules inside try/except** as they're only available after database opens
6. **Use auto_wait() carefully** - it can hang on large binaries

## Python API Modules

After database is open, these modules become available:

- `ida_auto` - Auto-analysis control
- `ida_funcs` - Function management
- `ida_name` - Name management
- `ida_bytes` - Byte-level access
- `ida_segment` - Segment information
- `ida_xref` - Cross-references
- `idautils` - Utility functions
- `idc` - IDC compatibility layer
- `ida_hexrays` - Decompiler (if available)

## Alternative Approaches

For the TODO samples that have issues with idalib:
1. Use IDA GUI in batch mode with scripts
2. Use other tools like radare2, Ghidra, or Binary Ninja
3. Parse dynamic symbols directly with `nm -D` and analyze with custom tools
4. Our `reverse` tool already handles most cases except these edge cases