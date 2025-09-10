# reverse

`reverse` finds XXTEA encryption keys in ARM64 Android/iOS Cocos apps.

How it works:
- Disassembles ARM64 functions
- Tracks register values and stack objects
- Recognizes `std::string` patterns (inline and heap)
- Finds calls to XXTEA functions
- Extracts encryption keys and signatures
- Shows annotated assembly code


Special thanks to Taha Draidia for the guidance and feedback that made this proof-of-concept possible.

## Demo

![Demo](vhs/demo.gif)

## Usage

**TUI**:
```bash
make
./reverse libcocos2djs.so
```

**No TUI**:
```bash
./reverse libcocos2djs.so --no-tui
```

Entry points assembly with annotations  
```bash
./reverse libcocos2djs.so --no-tui --full
```

JSON output for scripting

```bash
./reverse libcocos2djs.so --json
```

## Encryption and Decryption

### Encrypt files

Encrypt a file with XXTEA:
```bash
./reverse --encrypt --key "mykey" file.lua
```

Encrypt with a signature (prepended to encrypted data):
```bash
./reverse --encrypt --key "mykey" --signature "SIG" file.lua
```

Write encrypted output to file:
```bash
./reverse --encrypt --key "mykey" --signature "SIG" -w file.lua
# Creates file.luac (for .lua files)
# Creates file.jsc (for .js files)
# Creates file.encrypted (for other files)
```

Batch encrypt all .lua files:
```bash
find src -name "*.lua" -exec ./reverse --encrypt --key "mykey" --signature "SIG" -w {} \;
```

### Decrypt files

Decrypt a file with a known key:
```bash
./reverse --decrypt --key "key" encrypted.luac
```

Decrypt all jsc files in a directory:
```bash
find assets -name "*.jsc" -exec ./reverse --decrypt --key "key" -w {} \;
find assets -name "*.js" -exec prettier -w {} \;
```

Some Cocos2d-x games add a signature to encrypted files :

- The signature appears at the start of the file
- The encrypted data follows the signature  
- The tool strips the signature before decrypting

Ref: [ResourcesDecode.cpp](https://github.com/rtbhosale/nbg118/blob/920c4d4a48e91fce53062772622897341b8519a7/tools/pack_files/ResourcesDecode.cpp#L4)

Decrypt with signature:


```bash
./reverse --decrypt --key "key" --signature "sig" encrypted.luac
```

Decrypt all files with a specific signature:

```bash
./reverse --find-signature "sig" assets/ | \
  while read f; do
    ./reverse --decrypt --key "key" --signature "sig" -w "$f"
  done
```

**Bruteforce** key from .rodata section*

Use this when static analysis fails:

```bash
./reverse --decrypt -w --bruteforce libcocos2dlua.so encrypted.luac
```

with signature: 

```bash
./reverse --decrypt  -w --bruteforce --signature "sig" libcocos2dlua.so encrypted.luac
```

How `--bruteforce` works:

- Extracts all strings from the .rodata section
- Searches near the signature first (if provided) - much faster
- Tests each string as a key
- Tests shifted versions too (handles offset pointers)
- Detects gzip/zip compression
- Validates results by checking file headers

## Limitations

ARM64 only (no x86 or ARMv7)

## Author

Anthony Zboralski 
[@zboralski](https://x.com/zboralski) [github.com/zboralski](https://github.com/zboralski)

## License

MIT License - see LICENSE file for details.
