package main

import (
	"fmt"
	"github.com/xxtea/xxtea-go/xxtea"
)

func testKey(key string) {
	data := []byte("test data")
	keyBytes := []byte(key)
	
	encrypted := xxtea.Encrypt(data, keyBytes)
	if encrypted == nil {
		fmt.Printf("Key %q (len=%d): Encryption failed\n", key, len(key))
		return
	}
	
	decrypted := xxtea.Decrypt(encrypted, keyBytes)
	if decrypted == nil {
		fmt.Printf("Key %q (len=%d): Decryption failed\n", key, len(key))
		return
	}
	
	if string(decrypted) == string(data) {
		fmt.Printf("Key %q (len=%d): SUCCESS\n", key, len(key))
	} else {
		fmt.Printf("Key %q (len=%d): Data mismatch\n", key, len(key))
	}
}

func main() {
	fmt.Println("Testing XXTEA with various key lengths:")
	testKey("")          // Empty
	testKey("A")         // 1 char
	testKey("AB")        // 2 chars
	testKey("ABC")       // 3 chars
	testKey("ABCD")      // 4 chars
	testKey("TESTKEY")   // Normal key
}