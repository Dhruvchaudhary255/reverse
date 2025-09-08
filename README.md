# reverse

`reverse` is a static analysis tool for reverse-engineering ARM64 Android/iOS binaries, focused on automatically detecting XXTEA key usage in Cocos2d-x based games.

It works by:
- Disassembling functions (`TraceDisasm`) and annotating ARM64 instructions with semantic meaning.
- Tracking register state and stack objects (e.g. `std::string` built with Small String Optimization).
- Recognizing patterns like inline vs. heap strings, member function calls, and vtable dispatch chains.
- Flagging XOR operations that may indicate string obfuscation.
- Extracting parameters passed into XXTEA-related functions (`jsb_set_xxtea_key`, `BaseGame::setXXTeaKey`, etc.).
- Producing annotated listings and call findings with comments such as recovered keys/signatures.

In short: run `./reverse` on a target binary, and it will trace through symbolized functions, resolve indirect/virtual calls, reconstruct `std::string` arguments, and highlight where and how XXTEA keys are set. This dramatically shortens the time needed to locate and recover encryption keys in obfuscated mobile games.

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

Cocos2d-x games that use `ResourcesDecode.cpp` may prepend a signature to encrypted files. This signature acts as a magic number to identify encrypted content. The signature is not part of the XXTEA algorithm itself - it's added by the game's `ResourcesDecode.cpp` implementation.

When a file has a signature:
1. The signature bytes appear at the start of the file
2. The actual XXTEA-encrypted data follows immediately after
3. During decryption, the signature is stripped and the remaining bytes are decrypted

Common signatures are short strings (3-10 bytes). The game checks for this signature before attempting decryption, allowing it to mix encrypted and unencrypted assets in the same directory.

For a reference implementation, see: [ResourcesDecode.cpp](https://github.com/yisiyidian/bbdc_k12/blob/ff52887bb43119826721b55f69537c28c28a4e74/tools/pack_files/ResourcesDecode.cpp)

## How it works

The tool:

1. Loads the binary and finds entry points (JNI_OnLoad, app init functions)
2. Disassembles ARM64 code and tracks register values
3. Recognizes std::string construction patterns
4. Identifies calls to XXTEA setter functions
5. Extracts the key and signature parameters

The analysis handles:
- Virtual function calls through vtables
- Inline strings (Small String Optimization)
- Heap-allocated strings
- Member function calling conventions
- PLT/GOT indirection

## Output format

The tool shows:
- Function name and address
- Key value and length
- Signature value (if present)
- Assembly code with annotations
- Call sites and targets

## Examples

Find keys in a game binary:
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

## Limitations

- ARM64 only (no x86 or ARMv7)
- Static analysis only (no runtime debugging)

## Author

Anthony Zboralski
- GitHub: [@gatopeich](https://github.com/gatopeich)
- X: [@gatopeich](https://x.com/gatopeich)

## License

MIT License - see LICENSE file for details.