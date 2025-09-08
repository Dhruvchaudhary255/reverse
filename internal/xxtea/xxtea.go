// Package xxtea implements the XXTEA encryption algorithm.
// This is a faithful port of the C++ implementation, preserving the exact logic.
package xxtea

import (
	"errors"
)

const (
	// DELTA is the key schedule constant
	DELTA = 0x9e3779b9
)

// mx implements the XXTEA_MX macro from the C++ code
// #define XXTEA_MX (z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (sum ^ y) + (k[p & 3 ^ e] ^ z)
func mx(sum, y, z uint32, p, e int, k []uint32) uint32 {
	return ((z>>5 ^ y<<2) + (y>>3 ^ z<<4)) ^ ((sum ^ y) + (k[(p&3)^e] ^ z))
}

// longEncrypt encrypts data in place (equivalent to xxtea_long_encrypt)
func longEncrypt(v []uint32, k []uint32) {
	n := len(v) - 1
	if n < 1 {
		return
	}
	
	var z = v[n]
	var y = v[0]
	var q = 6 + 52/(n+1)
	var sum uint32 = 0
	
	for q > 0 {
		sum += DELTA
		e := int((sum >> 2) & 3)
		for p := 0; p < n; p++ {
			y = v[p+1]
			v[p] += mx(sum, y, z, p, e, k)
			z = v[p]
		}
		y = v[0]
		v[n] += mx(sum, y, z, n, e, k)
		z = v[n]
		q--
	}
}

// longDecrypt decrypts data in place (equivalent to xxtea_long_decrypt)
func longDecrypt(v []uint32, k []uint32) {
	n := len(v) - 1
	if n < 1 {
		return
	}
	
	var z = v[n]
	var y = v[0]
	var q = 6 + 52/(n+1)
	var sum = uint32(q) * DELTA
	
	for sum != 0 {
		e := int((sum >> 2) & 3)
		for p := n; p > 0; p-- {
			z = v[p-1]
			v[p] -= mx(sum, y, z, p, e, k)
			y = v[p]
		}
		z = v[n]
		v[0] -= mx(sum, y, z, 0, e, k)
		y = v[0]
		sum -= DELTA
	}
}

// fixKeyLength ensures the key is exactly 16 bytes (equivalent to fix_key_length)
func fixKeyLength(key []byte) []byte {
	if len(key) >= 16 {
		return key[:16]
	}
	
	result := make([]byte, 16)
	copy(result, key)
	// Remaining bytes are already zero from make()
	return result
}

// toLongArray converts bytes to uint32 array (equivalent to xxtea_to_long_array)
func toLongArray(data []byte, includeLength bool) []uint32 {
	length := len(data)
	n := (length + 3) / 4 // Round up division
	
	var result []uint32
	if includeLength {
		result = make([]uint32, n+1)
		result[n] = uint32(length)
	} else {
		result = make([]uint32, n)
	}
	
	// Convert bytes to uint32 array (little-endian)
	for i := 0; i < length; i++ {
		result[i/4] |= uint32(data[i]) << ((i % 4) * 8)
	}
	
	return result
}

// toByteArray converts uint32 array to bytes (equivalent to xxtea_to_byte_array)
func toByteArray(data []uint32, includeLength bool) ([]byte, error) {
	length := len(data) * 4
	
	if includeLength {
		if len(data) == 0 {
			return nil, errors.New("invalid data length")
		}
		m := int(data[len(data)-1])
		if m < length-7 || m > length-4 {
			return nil, errors.New("invalid length in data")
		}
		length = m
	}
	
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		result[i] = byte((data[i/4] >> ((i % 4) * 8)) & 0xff)
	}
	
	return result, nil
}

// Encrypt encrypts data using XXTEA algorithm (equivalent to xxtea_encrypt)
func Encrypt(data []byte, key []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}
	
	// Fix key length to exactly 16 bytes
	fixedKey := fixKeyLength(key)
	
	// Convert data to long array with length included
	v := toLongArray(data, true)
	
	// Convert key to long array
	k := toLongArray(fixedKey, false)
	
	// Encrypt in place
	longEncrypt(v, k)
	
	// Convert back to byte array without length
	return toByteArray(v, false)
}

// Decrypt decrypts data using XXTEA algorithm (equivalent to xxtea_decrypt)
func Decrypt(data []byte, key []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}
	
	// Fix key length to exactly 16 bytes
	fixedKey := fixKeyLength(key)
	
	// Convert data to long array without length
	v := toLongArray(data, false)
	
	// Convert key to long array
	k := toLongArray(fixedKey, false)
	
	// Decrypt in place
	longDecrypt(v, k)
	
	// Convert back to byte array with length
	return toByteArray(v, true)
}

// EncryptString encrypts a string and returns the encrypted bytes
func EncryptString(text string, key string) ([]byte, error) {
	return Encrypt([]byte(text), []byte(key))
}

// DecryptString decrypts bytes and returns the decrypted string
func DecryptString(data []byte, key string) (string, error) {
	decrypted, err := Decrypt(data, []byte(key))
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}

// EncryptWithSignature encrypts data with both key and signature
// The signature is prepended to the data before encryption
func EncryptWithSignature(data []byte, key []byte, signature []byte) ([]byte, error) {
	if len(signature) > 0 {
		// Prepend signature to data
		combined := make([]byte, len(signature)+len(data))
		copy(combined, signature)
		copy(combined[len(signature):], data)
		return Encrypt(combined, key)
	}
	return Encrypt(data, key)
}

// DecryptWithSignature decrypts data and verifies/removes signature
func DecryptWithSignature(data []byte, key []byte, signature []byte) ([]byte, error) {
	decrypted, err := Decrypt(data, key)
	if err != nil {
		return nil, err
	}
	
	if len(signature) > 0 {
		if len(decrypted) < len(signature) {
			return nil, errors.New("decrypted data too short for signature")
		}
		
		// Verify signature
		for i := 0; i < len(signature); i++ {
			if decrypted[i] != signature[i] {
				return nil, errors.New("signature mismatch")
			}
		}
		
		// Remove signature
		return decrypted[len(signature):], nil
	}
	
	return decrypted, nil
}