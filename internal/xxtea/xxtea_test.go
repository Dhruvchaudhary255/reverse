package xxtea

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	tests := []struct {
		name string
		data string
		key  string
	}{
		{
			name: "simple text",
			data: "Hello, World!",
			key:  "1234567890",
		},
		{
			name: "empty key",
			data: "Test data",
			key:  "",
		},
		{
			name: "short key",
			data: "Another test",
			key:  "key",
		},
		{
			name: "exact 16 byte key",
			data: "Test with 16byte",
			key:  "1234567890123456",
		},
		{
			name: "long key (truncated to 16)",
			data: "Test with long key",
			key:  "12345678901234567890", // Will be truncated to 16 bytes
		},
		{
			name: "binary data",
			data: "\x00\x01\x02\x03\x04\x05\x06\x07",
			key:  "binarykey",
		},
		{
			name: "single byte",
			data: "a",
			key:  "key",
		},
		{
			name: "large data",
			data: "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.",
			key:  "secretkey123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt
			encrypted, err := Encrypt([]byte(tt.data), []byte(tt.key))
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			// Encrypted should be different from original
			if bytes.Equal(encrypted, []byte(tt.data)) {
				t.Error("Encrypted data is same as original")
			}

			// Decrypt
			decrypted, err := Decrypt(encrypted, []byte(tt.key))
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			// Decrypted should match original
			if !bytes.Equal(decrypted, []byte(tt.data)) {
				t.Errorf("Decrypted data doesn't match original\nOriginal:  %q\nDecrypted: %q", tt.data, string(decrypted))
			}
		})
	}
}

func TestEncryptDecryptString(t *testing.T) {
	text := "Hello, XXTEA!"
	key := "mysecretkey"

	encrypted, err := EncryptString(text, key)
	if err != nil {
		t.Fatalf("EncryptString failed: %v", err)
	}

	decrypted, err := DecryptString(encrypted, key)
	if err != nil {
		t.Fatalf("DecryptString failed: %v", err)
	}

	if decrypted != text {
		t.Errorf("Decrypted string doesn't match original\nOriginal:  %q\nDecrypted: %q", text, decrypted)
	}
}

func TestWithSignature(t *testing.T) {
	data := []byte("Secret message")
	key := []byte("encryptionkey")
	signature := []byte("SIG123")

	// Encrypt with signature
	encrypted, err := EncryptWithSignature(data, key, signature)
	if err != nil {
		t.Fatalf("EncryptWithSignature failed: %v", err)
	}

	// Decrypt with correct signature
	decrypted, err := DecryptWithSignature(encrypted, key, signature)
	if err != nil {
		t.Fatalf("DecryptWithSignature failed: %v", err)
	}

	if !bytes.Equal(decrypted, data) {
		t.Errorf("Decrypted data doesn't match original\nOriginal:  %q\nDecrypted: %q", data, decrypted)
	}

	// Try to decrypt with wrong signature
	wrongSig := []byte("WRONG!")
	_, err = DecryptWithSignature(encrypted, key, wrongSig)
	if err == nil {
		t.Error("Expected error with wrong signature, but got none")
	}
}

func TestFixKeyLength(t *testing.T) {
	tests := []struct {
		name     string
		key      []byte
		expected int
	}{
		{"empty key", []byte{}, 16},
		{"short key", []byte("short"), 16},
		{"exact 16 bytes", []byte("1234567890123456"), 16},
		{"long key", []byte("12345678901234567890"), 16},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixed := fixKeyLength(tt.key)
			if len(fixed) != tt.expected {
				t.Errorf("Expected key length %d, got %d", tt.expected, len(fixed))
			}

			// Verify padding is zeros
			if len(tt.key) < 16 {
				for i := len(tt.key); i < 16; i++ {
					if fixed[i] != 0 {
						t.Errorf("Expected zero padding at position %d, got %d", i, fixed[i])
					}
				}
			}
		})
	}
}

func TestKnownVectors(t *testing.T) {
	// Test with known XXTEA test vectors if available
	// These would be from the C++ implementation or other reference implementations
	tests := []struct {
		name      string
		plaintext string
		key       string
		expected  string // hex encoded ciphertext
	}{
		// Add known test vectors here when available
		// Example:
		// {
		//     name:      "reference vector 1",
		//     plaintext: "test",
		//     key:       "key",
		//     expected:  "hexencodedciphertext",
		// },
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := Encrypt([]byte(tt.plaintext), []byte(tt.key))
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			hexResult := hex.EncodeToString(encrypted)
			if hexResult != tt.expected {
				t.Errorf("Encryption mismatch\nExpected: %s\nGot:      %s", tt.expected, hexResult)
			}
		})
	}
}

func TestEdgeCases(t *testing.T) {
	// Test empty data
	_, err := Encrypt([]byte{}, []byte("key"))
	if err == nil {
		t.Error("Expected error with empty data")
	}

	// Test decrypt with invalid length marker
	// Create data that will have invalid length when decrypted
	invalidData := []byte{0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF}
	_, err = Decrypt(invalidData, []byte("key"))
	// This may or may not error depending on the random decryption result
	// The important thing is it doesn't panic
	_ = err
}

func TestRoundTrip(t *testing.T) {
	// Test multiple round trips to ensure stability
	original := []byte("Round trip test data")
	key := []byte("testkey123")

	data := original
	for i := 0; i < 3; i++ {
		encrypted, err := Encrypt(data, key)
		if err != nil {
			t.Fatalf("Encrypt round %d failed: %v", i+1, err)
		}

		decrypted, err := Decrypt(encrypted, key)
		if err != nil {
			t.Fatalf("Decrypt round %d failed: %v", i+1, err)
		}

		if !bytes.Equal(decrypted, original) {
			t.Errorf("Round %d: data mismatch", i+1)
		}

		data = original // Reset for next round
	}
}

func BenchmarkEncrypt(b *testing.B) {
	data := []byte("Benchmark test data for XXTEA encryption")
	key := []byte("benchmarkkey123")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Encrypt(data, key)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecrypt(b *testing.B) {
	data := []byte("Benchmark test data for XXTEA decryption")
	key := []byte("benchmarkkey123")
	encrypted, _ := Encrypt(data, key)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Decrypt(encrypted, key)
		if err != nil {
			b.Fatal(err)
		}
	}
}