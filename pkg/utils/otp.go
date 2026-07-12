package utils

import (
	"crypto/rand"
	"math/big"
)

func RandomString(length int, chars string) string {
	if length < 0 {
		panic("random string length must not be negative")
	}
	if length > 0 && len(chars) == 0 {
		panic("random string alphabet must not be empty")
	}
	result := make([]byte, length)
	max := big.NewInt(int64(len(chars)))
	for i := range length {
		randomIndex, err := rand.Int(rand.Reader, max)
		if err != nil {
			// Entropy failure makes OTP/JTI generation unsafe. Failing closed is
			// preferable to issuing predictable authentication material.
			panic("secure random source unavailable: " + err.Error())
		}
		result[i] = chars[randomIndex.Int64()]
	}
	return string(result)
}

func RandomOtp(length int) string {
	return RandomString(length, "1234567890")
}
