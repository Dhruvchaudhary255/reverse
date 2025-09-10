# reverse

`reverse` finds XXTEA encryption keys in ARM64 Android/iOS Cocos apps.

The tool:
- Disassembles ARM64 functions
- Tracks register values and stack objects
- Recognizes `std::string` patterns (inline and heap)
- Finds calls to XXTEA functions
- Extracts encryption keys and signatures
- Shows annotated assembly code

Special thanks to Taha Draidia for the guidance and feedback that made this proof-of-concept possible.

## Demo

![Demo](vhs/demo.gif)

## Installation

```bash
make build
```

## Basic usage

Analyze a binary:
```bash
./reverse libcocos2djs.so
```

This opens an interactive viewer. Press Tab to switch between panels. Press q to quit.

## Command options

### Analysis modes

**JSON output** for scripting:
```bash
./reverse --json libcocos2djs.so
```

**Summary only** without the interactive viewer:
```bash
./reverse --no-tui libcocos2djs.so
```

**Detailed call chains** with annotations:
```bash
./reverse --no-tui --full libcocos2djs.so
```

### Decryption

**Decrypt a file** with a known key:
```bash
./reverse --decrypt --key "mykey" encrypted.luac
```

**Decrypt with signature** (prepended to file):
```bash
./reverse --decrypt --key "mykey" --signature "sig" encrypted.luac
```

**Write output to file** instead of stdout:
```bash
./reverse --decrypt --key "mykey" -w encrypted.luac
# Creates encrypted.lua (for .luac files)
# Creates encrypted.js (for .jsc files)  
# Creates encrypted-decrypted.ext (for other files)
```

**Brute force key from .rodata section**:
```bash
# Try all strings from .rodata as potential keys
./reverse --decrypt --bruteforce libcocos2dlua.so encrypted.luac

# With signature (searches near signature first - much faster)
./reverse --decrypt --bruteforce --signature "SIG" libcocos2dlua.so encrypted.luac

# Write decrypted output to file
./reverse --decrypt --bruteforce --signature "sig" -w libcocos2dlua.so encrypted.luac
```

Bruteforce mode:
- Extracts all strings from the .rodata section
- Searches near the signature first (if provided)
- Tests each string as a key
- Tests shifted versions too (handles offset pointers)
- Detects gzip/zip compression
- Validates results by checking file headers

Use this when function names are stripped but the key exists in .rodata.

### Finding encrypted files

**Find files with a signature** in a directory:
```bash
./reverse --find-signature "SIGNATURE" /path/to/assets
```

**Non-recursive search**:
```bash
./reverse --find-signature "SIGNATURE" /path/to/dir -r=false
```

### About signatures

Some Cocos2d-x games add a signature to encrypted files. The signature marks which files are encrypted.

How signatures work:
1. The signature appears at the start of the file
2. The encrypted data follows the signature
3. The tool strips the signature before decrypting

Signatures are usually 3-10 bytes. Games use them to mix encrypted and plain files in one folder.

For a reference implementation, see: [ResourcesDecode.cpp](https://github.com/yisiyidian/bbdc_k12/blob/ff52887bb43119826721b55f69537c28c28a4e74/tools/pack_files/ResourcesDecode.cpp)

## How it works

Steps:
1. Load the binary and find entry points
2. Disassemble ARM64 code
3. Track register values
4. Find XXTEA function calls
5. Extract keys and signatures

The tool handles:
- Virtual function calls
- Inline strings (SSO)
- Heap strings
- Member functions
- PLT/GOT jumps

## Output format

The tool shows:
- Function name and address
- Key value and length
- Signature value (if present)
- Assembly code with annotations
- Call sites and targets

## Examples

Find keys in a Cocos library:
```bash
./reverse libcocos2djs.so --no-tui
```

Decrypt all Lua files in a directory:
```bash
for f in assets/*.luac; do
  ./reverse --decrypt --key "YOUR_KEY" -w "$f"
done
```

Find all files with a specific signature:
```bash
./reverse --find-signature "SIGNATURE" gamedata/
```

Batch decrypt files with signature:
```bash
./reverse --find-signature "SIGNATURE" assets/ | \
  grep '\.luac$' | \
  while read f; do
    ./reverse --decrypt --key "KEY" --signature "SIGNATURE" -w "assets/$f"
  done
```

Batch decrypt using find:
```bash
# Decrypt all .luac files
find assets -name "*.luac" -exec ./reverse --decrypt --key "KEY" --signature "SIGNATURE" -w {} \;

# Without signature
find assets -name "*.luac" -exec ./reverse --decrypt --key "KEY" -w {} \;
```

## Limitations

- ARM64 only (no x86 or ARMv7
- Static analysis only (no runtime debugging)

## Author

Anthony Zboralski
- GitHub: [@zboralski](https://github.com/zboralski)
- X: [@zboralski](https://x.com/zboralski)

## License

MIT License - see LICENSE file for details.
