package common

import (
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"math/rand"
	"sync"
	"time"
)

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))

const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

// ECDSASignature for ECDSA signature marshaling
type ECDSASignature struct {
	R, S *big.Int
}

// PanicIfEmpty panics if the given string is empty
func PanicIfEmpty(val string, msg string) {
	if val == "" {
		panic(msg)
	}
}

// StringOrNil returns the given string or nil when empty
func StringOrNil(str string) *string {
	if str == "" {
		return nil
	}
	return &str
}

// RandomString generates a random string of the given length
func RandomString(n int) string {
	b := make([]byte, n)

	// put a mutex around this local source, as it's not concurrent safe
	mutex := &sync.Mutex{}
	mutex.Lock()
	defer mutex.Unlock()
	var localSource = rand.NewSource(time.Now().UnixNano())

	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, localSource.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = localSource.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(charset) {
			b[i] = charset[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}

// SHA256 is a convenience method to return the sha256 hash of the given input
func SHA256(str string) string {
	digest := sha256.New()
	digest.Write([]byte(str))
	return hex.EncodeToString(digest.Sum(nil))
}

// RandomBytes generates a cryptographically random byte array
func RandomBytes(length int) ([]byte, error) {
	b := make([]byte, length)

	_, err := cryptorand.Read(b)
	if err != nil {
		return nil, fmt.Errorf("error generating random bytes %s", err.Error())
	}
	return b, nil
}
