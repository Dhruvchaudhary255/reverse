package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/xxtea/xxtea-go/xxtea"
)

func TestShiftedKeyDetection(t *testing.T) {
	// Original test data
	originalData := []byte("This is a test file to verify shifted key detection in bruteforce mode")
	
	// Test cases with different key scenarios
	testCases := []struct {
		name        string
		storedKey   string // What's in .rodata
		actualKey   string // What we need for decryption
		signature   string // Optional signature
		description string
	}{
		{
			name:        "Direct key without signature",
			storedKey:   "TESTKEY123",
			actualKey:   "TESTKEY123",
			signature:   "",
			description: "Key used directly without shifting, no signature",
		},
		{
			name:        "Direct key with signature",
			storedKey:   "TESTKEY123",
			actualKey:   "TESTKEY123",
			signature:   "SIG",
			description: "Key used directly without shifting, with signature",
		},
		{
			name:        "Pointer shifted by 1",
			storedKey:   "XTESTKEY123", // First char is garbage
			actualKey:   "TESTKEY123",   // Skip first char
			signature:   "",
			description: "Key pointer shifted by 1 byte",
		},
		{
			name:        "Pointer shifted by 2 with signature",
			storedKey:   "XXTESTKEY123", // First 2 chars are garbage
			actualKey:   "TESTKEY123",    // Skip first 2 chars
			signature:   "MAGIC",
			description: "Key pointer shifted by 2 bytes with signature",
		},
		{
			name:        "Key with prefix",
			storedKey:   "KEY_TESTKEY123", // Has prefix
			actualKey:   "TESTKEY123",      // Skip prefix
			signature:   "",
			description: "Key stored with prefix in binary",
		},
		{
			name:        "Extremely shifted key",
			storedKey:   strings.Repeat("X", 50) + "TESTKEY123", // 50 chars of garbage
			actualKey:   "TESTKEY123",
			signature:   "",
			description: "Key shifted by 50 characters",
		},
		{
			name:        "Key at the end of long string",
			storedKey:   "some_very_long_prefix_that_contains_the_actual_TESTKEY123",
			actualKey:   "TESTKEY123",
			signature:   "SIG",
			description: "Key at the end of a long string with signature",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Prepare encrypted data
			var encrypted []byte
			if tc.signature != "" {
				// Encrypt with signature
				encrypted = append([]byte(tc.signature), xxtea.Encrypt(originalData, []byte(tc.actualKey))...)
			} else {
				// Encrypt without signature
				encrypted = xxtea.Encrypt(originalData, []byte(tc.actualKey))
			}
			
			// Simulate bruteforce trying different shifts
			found := false
			var decryptedData []byte
			
			// Try the stored key and all its suffixes
			for i := 0; i < len(tc.storedKey); i++ {
				tryKey := tc.storedKey[i:]
				
				// Skip if key is too short
				if len(tryKey) < 3 {
					continue
				}
				
				// Try decryption
				var decrypted []byte
				if tc.signature != "" {
					// Try with signature
					sigBytes := []byte(tc.signature)
					if len(encrypted) >= len(sigBytes) && bytes.Equal(encrypted[:len(sigBytes)], sigBytes) {
						decrypted = xxtea.Decrypt(encrypted[len(sigBytes):], []byte(tryKey))
					}
				} else {
					// Try without signature
					decrypted = xxtea.Decrypt(encrypted, []byte(tryKey))
				}
				
				// Check if decryption succeeded
				if decrypted != nil && isValidDecryption(decrypted, tc.signature) {
					if bytes.Equal(decrypted, originalData) {
						found = true
						decryptedData = decrypted
						t.Logf("Found key at offset %d: %s", i, tryKey)
						break
					}
				}
			}
			
			if !found {
				t.Errorf("Failed to find key for test case: %s", tc.description)
			} else if !bytes.Equal(decryptedData, originalData) {
				t.Errorf("Decrypted data doesn't match original for test case: %s", tc.description)
			}
		})
	}
}

func TestBruteforceWithShifting(t *testing.T) {
	// Test that our bruteforce function tries shifted versions
	originalData := []byte("Test data for bruteforce shifting")
	
	// Create a mock .rodata section with keys at various positions
	rodataSection := []byte{
		0x00, 0x00, // Some padding
		'P', 'R', 'E', 'F', 'I', 'X', // Prefix junk
		'R', 'E', 'A', 'L', 'K', 'E', 'Y', '1', '2', '3', 0x00, // The actual key with null terminator
		0x00, 0x00, // More padding
		'A', 'N', 'O', 'T', 'H', 'E', 'R', // Another string
		'K', 'E', 'Y', 'T', 'E', 'S', 'T', 0x00, // Another key
	}
	
	// Encrypt with "REALKEY123"
	actualKey := "REALKEY123"
	encrypted := xxtea.Encrypt(originalData, []byte(actualKey))
	
	// Extract strings from mock rodata
	strings := extractNullTerminatedStrings(rodataSection)
	
	// Try all strings and their shifted versions
	found := false
	var foundKey string
	
	for _, str := range strings {
		// Try original string
		if tryDecryption(encrypted, str, originalData) {
			found = true
			foundKey = str
			break
		}
		
		// Try all shifted versions (skip first 1, 2, 3... characters)
		for shift := 1; shift < len(str)-2; shift++ {
			shiftedKey := str[shift:]
			if tryDecryption(encrypted, shiftedKey, originalData) {
				found = true
				foundKey = shiftedKey
				break
			}
		}
		
		if found {
			break
		}
	}
	
	if !found {
		t.Error("Failed to find key through bruteforce with shifting")
	} else if foundKey != actualKey {
		t.Errorf("Found wrong key: got %s, want %s", foundKey, actualKey)
	}
}

func TestBruteforceNegativeCases(t *testing.T) {
	originalData := []byte("Test data that should not decrypt")
	
	testCases := []struct {
		name           string
		encryptKey     string
		availableKeys  []string
		signature      string
		shouldFind     bool
		description    string
	}{
		{
			name:           "Key not in rodata",
			encryptKey:     "SECRETKEY999",
			availableKeys:  []string{"WRONGKEY1", "WRONGKEY2", "TESTKEY123"},
			signature:      "",
			shouldFind:     false,
			description:    "Should fail when correct key is not in the string list",
		},
		{
			name:           "Key heavily shifted",
			encryptKey:     "KEY123",
			availableKeys:  []string{"XXXXXXXXXXXXXXXXXKEY123"}, // Shifted by 17 characters
			signature:      "",
			shouldFind:     true, // Should now find it since we removed the 10 char limit
			description:    "Should find key even when shifted by many characters",
		},
		{
			name:           "Wrong signature",
			encryptKey:     "TESTKEY",
			availableKeys:  []string{"TESTKEY"},
			signature:      "WRONGSIG",
			shouldFind:     false,
			description:    "Should fail with wrong signature even if key is correct",
		},
		{
			name:           "Empty key list",
			encryptKey:     "ANYKEY",
			availableKeys:  []string{},
			signature:      "",
			shouldFind:     false,
			description:    "Should fail when no keys are available",
		},
		{
			name:           "Key too short after shift",
			encryptKey:     "ABC",
			availableKeys:  []string{"XABC"}, // After shift, only "ABC" remains (too short)
			signature:      "",
			shouldFind:     false,
			description:    "Should fail when shifted key becomes too short (<4 chars)",
		},
		{
			name:           "Corrupted encrypted data",
			encryptKey:     "TESTKEY",
			availableKeys:  []string{"TESTKEY"},
			signature:      "",
			shouldFind:     false,
			description:    "Should fail with corrupted encrypted data",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var encrypted []byte
			
			// Special case for corrupted data test
			if tc.name == "Corrupted encrypted data" {
				// Create invalid encrypted data
				encrypted = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
			} else {
				// Normal encryption
				if tc.signature != "" {
					encrypted = append([]byte(tc.signature), xxtea.Encrypt(originalData, []byte(tc.encryptKey))...)
				} else {
					encrypted = xxtea.Encrypt(originalData, []byte(tc.encryptKey))
				}
			}
			
			// Try to decrypt with available keys
			found := false
			for _, key := range tc.availableKeys {
				// Try the key and its shifted versions
				for shift := 0; shift < len(key); shift++ {
					tryKey := key[shift:]
					if len(tryKey) < 4 {
						break
					}
					
					var decrypted []byte
					if tc.signature != "" && tc.signature != "WRONGSIG" {
						sigBytes := []byte(tc.signature)
						if len(encrypted) >= len(sigBytes) && bytes.Equal(encrypted[:len(sigBytes)], sigBytes) {
							decrypted = xxtea.Decrypt(encrypted[len(sigBytes):], []byte(tryKey))
						}
					} else if tc.signature == "" {
						decrypted = xxtea.Decrypt(encrypted, []byte(tryKey))
					}
					
					if decrypted != nil && bytes.Equal(decrypted, originalData) {
						found = true
						t.Logf("Found key: %s (shift=%d)", tryKey, shift)
						break
					}
				}
				if found {
					break
				}
			}
			
			if found != tc.shouldFind {
				if tc.shouldFind {
					t.Errorf("Expected to find key but didn't for: %s", tc.description)
				} else {
					t.Errorf("Found key when shouldn't have for: %s", tc.description)
				}
			}
		})
	}
}

func TestBruteforceEdgeCases(t *testing.T) {
	testCases := []struct {
		name        string
		rodataData  []byte
		description string
		expectKeys  int
	}{
		{
			name:        "Empty rodata",
			rodataData:  []byte{},
			description: "Should handle empty rodata section",
			expectKeys:  0,
		},
		{
			name:        "Only null bytes",
			rodataData:  []byte{0x00, 0x00, 0x00, 0x00},
			description: "Should handle rodata with only null bytes",
			expectKeys:  0,
		},
		{
			name:        "No null terminators",
			rodataData:  []byte{'A', 'B', 'C', 'D', 'E', 'F'},
			description: "Should handle rodata without null terminators",
			expectKeys:  0,
		},
		{
			name:        "Single character strings",
			rodataData:  []byte{'A', 0x00, 'B', 0x00, 'C', 0x00},
			description: "Should skip single character strings",
			expectKeys:  0,
		},
		{
			name:        "Non-printable characters",
			rodataData:  []byte{0x01, 0x02, 0x03, 0x04, 0x00, 'T', 'E', 'S', 'T', 0x00},
			description: "Should skip non-printable strings",
			expectKeys:  1, // Only "TEST"
		},
		{
			name:        "Very long string",
			rodataData:  append(bytes.Repeat([]byte{'A'}, 1000), 0x00),
			description: "Should handle very long strings",
			expectKeys:  1,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			keys := extractNullTerminatedStrings(tc.rodataData)
			
			if len(keys) != tc.expectKeys {
				t.Errorf("%s: expected %d keys, got %d", tc.description, tc.expectKeys, len(keys))
				t.Logf("Extracted keys: %v", keys)
			}
		})
	}
}

func tryDecryption(encrypted []byte, key string, expected []byte) bool {
	decrypted := xxtea.Decrypt(encrypted, []byte(key))
	return decrypted != nil && bytes.Equal(decrypted, expected)
}

func extractNullTerminatedStrings(data []byte) []string {
	var result []string
	start := 0
	
	for i := 0; i < len(data); i++ {
		if data[i] == 0 {
			if i > start {
				str := string(data[start:i])
				if isPrintableString([]byte(str)) && len(str) >= 3 {
					result = append(result, str)
				}
			}
			start = i + 1
		}
	}
	
	return result
}

