package cmd

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFindSignature(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "find-signature-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Test signature
	signature := "TESTSIG"
	sigBytes := []byte(signature)

	// Create test directory structure
	testFiles := map[string][]byte{
		"file1.txt":                     append(sigBytes, []byte("content1")...),
		"file2.txt":                     []byte("no signature here"),
		"subdir/file3.txt":              append(sigBytes, []byte("content3")...),
		"subdir/file4.txt":              []byte("other content"),
		"subdir/nested/file5.txt":       append(sigBytes, []byte("content5")...),
		"subdir/nested/file6.txt":       []byte("more content"),
		"another/file7.txt":             append(sigBytes, []byte("content7")...),
	}

	// Create test files
	for path, content := range testFiles {
		fullPath := filepath.Join(tmpDir, path)
		dir := filepath.Dir(fullPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fullPath, content, 0644); err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		name      string
		dir       string
		signature string
		recursive bool
		expected  []string
	}{
		{
			name:      "recursive search",
			dir:       tmpDir,
			signature: signature,
			recursive: true,
			expected: []string{
				filepath.Join(tmpDir, "file1.txt"),
				filepath.Join(tmpDir, "subdir/file3.txt"),
				filepath.Join(tmpDir, "subdir/nested/file5.txt"),
				filepath.Join(tmpDir, "another/file7.txt"),
			},
		},
		{
			name:      "non-recursive search",
			dir:       tmpDir,
			signature: signature,
			recursive: false,
			expected: []string{
				filepath.Join(tmpDir, "file1.txt"),
			},
		},
		{
			name:      "search in subdirectory",
			dir:       filepath.Join(tmpDir, "subdir"),
			signature: signature,
			recursive: true,
			expected: []string{
				filepath.Join(tmpDir, "subdir/file3.txt"),
				filepath.Join(tmpDir, "subdir/nested/file5.txt"),
			},
		},
		{
			name:      "no matches",
			dir:       tmpDir,
			signature: "NOMATCH",
			recursive: true,
			expected:  []string{},
		},
		{
			name:      "relative path preserved",
			dir:       "subdir",
			signature: signature,
			recursive: true,
			expected: []string{
				"subdir/file3.txt",
				"subdir/nested/file5.txt",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Change to tmpDir for relative path test
			if tt.name == "relative path preserved" {
				oldDir, _ := os.Getwd()
				os.Chdir(tmpDir)
				defer os.Chdir(oldDir)
			}

			// Capture output
			old := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			// Run the function
			err := runFindSignature(tt.dir, tt.signature, tt.recursive)
			
			// Restore stdout
			w.Close()
			os.Stdout = old

			if err != nil {
				t.Errorf("runFindSignature() error = %v", err)
				return
			}

			// Read captured output
			var buf bytes.Buffer
			io.Copy(&buf, r)
			output := buf.String()

			// Parse output lines
			lines := strings.Split(strings.TrimSpace(output), "\n")
			if output == "" {
				lines = []string{}
			}

			// Check number of results
			if len(lines) != len(tt.expected) {
				t.Errorf("got %d results, want %d\nGot: %v\nWant: %v", 
					len(lines), len(tt.expected), lines, tt.expected)
				return
			}

			// Check each expected file is in output
			for _, expected := range tt.expected {
				found := false
				for _, line := range lines {
					if line == expected {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected file %s not found in output\nGot: %v", expected, lines)
				}
			}
		})
	}
}

func TestFindSignatureEdgeCases(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "find-signature-edge-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	tests := []struct {
		name        string
		setup       func() string
		signature   string
		shouldError bool
	}{
		{
			name: "empty signature",
			setup: func() string {
				return tmpDir
			},
			signature:   "",
			shouldError: false, // Empty signature should match all files at position 0
		},
		{
			name: "very long signature",
			setup: func() string {
				longSig := strings.Repeat("A", 1000)
				testFile := filepath.Join(tmpDir, "longfile.txt")
				os.WriteFile(testFile, []byte(longSig+"content"), 0644)
				return tmpDir
			},
			signature:   strings.Repeat("A", 1000),
			shouldError: false,
		},
		{
			name: "binary signature",
			setup: func() string {
				binarySig := []byte{0x00, 0x01, 0x02, 0x03}
				testFile := filepath.Join(tmpDir, "binary.bin")
				os.WriteFile(testFile, append(binarySig, []byte("data")...), 0644)
				return tmpDir
			},
			signature:   string([]byte{0x00, 0x01, 0x02, 0x03}),
			shouldError: false,
		},
		{
			name: "non-existent directory",
			setup: func() string {
				return filepath.Join(tmpDir, "nonexistent")
			},
			signature:   "TEST",
			shouldError: true,
		},
		{
			name: "file instead of directory",
			setup: func() string {
				testFile := filepath.Join(tmpDir, "file.txt")
				os.WriteFile(testFile, []byte("content"), 0644)
				return testFile
			},
			signature:   "TEST",
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := tt.setup()
			
			// Capture output
			old := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			err := runFindSignature(dir, tt.signature, true)
			
			w.Close()
			os.Stdout = old
			
			// Drain the pipe
			io.Copy(io.Discard, r)

			if (err != nil) != tt.shouldError {
				t.Errorf("runFindSignature() error = %v, shouldError = %v", err, tt.shouldError)
			}
		})
	}
}