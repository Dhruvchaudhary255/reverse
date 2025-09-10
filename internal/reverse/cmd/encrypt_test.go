package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"reverse/internal/xxtea"
)

func TestRunEncrypt(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "encrypt-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	testContent := []byte("This is test content for encryption")
	testFile := filepath.Join(tmpDir, "test.lua")
	if err := os.WriteFile(testFile, testContent, 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		filepath  string
		key       string
		signature string
		writeFile bool
		wantErr   bool
	}{
		{
			name:      "encrypt with key only",
			filepath:  testFile,
			key:       "TESTKEY123",
			signature: "",
			writeFile: false,
			wantErr:   false,
		},
		{
			name:      "encrypt with signature",
			filepath:  testFile,
			key:       "TESTKEY123",
			signature: "SIG",
			writeFile: false,
			wantErr:   false,
		},
		{
			name:      "encrypt and write to file",
			filepath:  testFile,
			key:       "TESTKEY123",
			signature: "SIG",
			writeFile: true,
			wantErr:   false,
		},
		{
			name:      "encrypt non-existent file",
			filepath:  filepath.Join(tmpDir, "nonexistent.lua"),
			key:       "TESTKEY123",
			signature: "",
			writeFile: false,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture stdout for non-write tests
			var buf bytes.Buffer
			if !tt.writeFile {
				old := os.Stdout
				r, w, _ := os.Pipe()
				os.Stdout = w

				err := runEncrypt(tt.filepath, tt.key, tt.signature, tt.writeFile)

				w.Close()
				os.Stdout = old
				buf.ReadFrom(r)

				if (err != nil) != tt.wantErr {
					t.Errorf("runEncrypt() error = %v, wantErr %v", err, tt.wantErr)
					return
				}

				if !tt.wantErr {
					output := buf.Bytes()

					// Verify signature is prepended if provided
					if tt.signature != "" {
						sigBytes := []byte(tt.signature)
						if !bytes.HasPrefix(output, sigBytes) {
							t.Errorf("Expected signature %q at beginning of output", tt.signature)
						}
						// Remove signature for decryption test
						output = output[len(sigBytes):]
					}

					// Try to decrypt to verify encryption worked
					decrypted, err := xxtea.Decrypt(output, []byte(tt.key))
					if err != nil {
						t.Errorf("Failed to decrypt encrypted output: %v", err)
					}
					if !bytes.Equal(decrypted, testContent) {
						t.Errorf("Decrypted content doesn't match original")
					}
				}
			} else {
				// Test file writing
				err := runEncrypt(tt.filepath, tt.key, tt.signature, tt.writeFile)
				if (err != nil) != tt.wantErr {
					t.Errorf("runEncrypt() error = %v, wantErr %v", err, tt.wantErr)
					return
				}

				if !tt.wantErr {
					// Check output file exists
					outputPath := filepath.Join(tmpDir, "test.luac")
					if _, err := os.Stat(outputPath); err != nil {
						t.Errorf("Output file not created: %v", err)
					}

					// Read and verify encrypted file
					encrypted, err := os.ReadFile(outputPath)
					if err != nil {
						t.Errorf("Failed to read encrypted file: %v", err)
					}

					// Verify signature if provided
					if tt.signature != "" {
						sigBytes := []byte(tt.signature)
						if !bytes.HasPrefix(encrypted, sigBytes) {
							t.Errorf("Expected signature %q at beginning of file", tt.signature)
						}
						encrypted = encrypted[len(sigBytes):]
					}

					// Decrypt and verify
					decrypted, err := xxtea.Decrypt(encrypted, []byte(tt.key))
					if err != nil {
						t.Errorf("Failed to decrypt file: %v", err)
					}
					if !bytes.Equal(decrypted, testContent) {
						t.Errorf("Decrypted content doesn't match original")
					}

					// Clean up output file
					os.Remove(outputPath)
				}
			}
		})
	}
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "roundtrip-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	tests := []struct {
		name      string
		content   []byte
		key       string
		signature string
	}{
		{
			name:      "simple text",
			content:   []byte("Hello, World!"),
			key:       "KEY123",
			signature: "",
		},
		{
			name:      "with signature",
			content:   []byte("Test with signature"),
			key:       "MYKEY",
			signature: "TESTSIG",
		},
		{
			name:      "binary data",
			content:   []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD},
			key:       "BINKEY",
			signature: "BIN",
		},
		{
			name:      "large content",
			content:   bytes.Repeat([]byte("A"), 10000),
			key:       "LARGE",
			signature: "BIG",
		},
		{
			name:      "unicode content",
			content:   []byte("Hello 世界 🌍"),
			key:       "UNICODE",
			signature: "UTF8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test file
			testFile := filepath.Join(tmpDir, "test.txt")
			if err := os.WriteFile(testFile, tt.content, 0644); err != nil {
				t.Fatal(err)
			}

			// Encrypt
			var encBuf bytes.Buffer
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			if err := runEncrypt(testFile, tt.key, tt.signature, false); err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			w.Close()
			os.Stdout = oldStdout
			encBuf.ReadFrom(r)
			encrypted := encBuf.Bytes()

			// Write encrypted data to file for decryption
			encFile := filepath.Join(tmpDir, "encrypted.bin")
			if err := os.WriteFile(encFile, encrypted, 0644); err != nil {
				t.Fatal(err)
			}

			// Decrypt
			var decBuf bytes.Buffer
			r, w, _ = os.Pipe()
			os.Stdout = w

			if err := runDecrypt(encFile, tt.key, tt.signature, false); err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			w.Close()
			os.Stdout = oldStdout
			decBuf.ReadFrom(r)
			decrypted := decBuf.Bytes()

			// Verify roundtrip
			if !bytes.Equal(decrypted, tt.content) {
				t.Errorf("Roundtrip failed: got %v, want %v", decrypted, tt.content)
			}
		})
	}
}

func TestEncryptFileExtensions(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ext-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	tests := []struct {
		inputFile   string
		outputFile  string
	}{
		{
			inputFile:  "test.lua",
			outputFile: "test.luac",
		},
		{
			inputFile:  "test.js",
			outputFile: "test.jsc",
		},
		{
			inputFile:  "test.txt",
			outputFile: "test.txt.encrypted",
		},
		{
			inputFile:  "noext",
			outputFile: "noext.encrypted",
		},
	}

	for _, tt := range tests {
		t.Run(tt.inputFile, func(t *testing.T) {
			// Create input file
			inputPath := filepath.Join(tmpDir, tt.inputFile)
			if err := os.WriteFile(inputPath, []byte("test"), 0644); err != nil {
				t.Fatal(err)
			}

			// Encrypt with write flag
			if err := runEncrypt(inputPath, "KEY", "", true); err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// Check output file exists
			outputPath := filepath.Join(tmpDir, tt.outputFile)
			if _, err := os.Stat(outputPath); err != nil {
				t.Errorf("Expected output file %s not created", tt.outputFile)
			}

			// Clean up
			os.Remove(outputPath)
		})
	}
}