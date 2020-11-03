// Implements HTTP request and response signing and verification. Supports the
// major MAC and asymmetric key signature algorithms. It has several safety
// restrictions: One, none of the widely known non-cryptographically safe
// algorithms are permitted; Two, the RSA SHA256 algorithms must be available in
// the binary (and it should, barring export restrictions); Finally, the library
// assumes either the 'Authorizationn' or 'Signature' headers are to be set (but
// not both).
package httpsig

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Algorithm specifies a cryptography secure algorithm for signing HTTP requests
// and responses.
type Algorithm string

const (
	// MAC-based algoirthms.
	HMAC_SHA224      Algorithm = hmacPrefix + "-" + sha224String
	HMAC_SHA256      Algorithm = hmacPrefix + "-" + sha256String
	HMAC_SHA384      Algorithm = hmacPrefix + "-" + sha384String
	HMAC_SHA512      Algorithm = hmacPrefix + "-" + sha512String
	HMAC_RIPEMD160   Algorithm = hmacPrefix + "-" + ripemd160String
	HMAC_SHA3_224    Algorithm = hmacPrefix + "-" + sha3_224String
	HMAC_SHA3_256    Algorithm = hmacPrefix + "-" + sha3_256String
	HMAC_SHA3_384    Algorithm = hmacPrefix + "-" + sha3_384String
	HMAC_SHA3_512    Algorithm = hmacPrefix + "-" + sha3_512String
	HMAC_SHA512_224  Algorithm = hmacPrefix + "-" + sha512_224String
	HMAC_SHA512_256  Algorithm = hmacPrefix + "-" + sha512_256String
	HMAC_BLAKE2S_256 Algorithm = hmacPrefix + "-" + blake2s_256String
	HMAC_BLAKE2B_256 Algorithm = hmacPrefix + "-" + blake2b_256String
	HMAC_BLAKE2B_384 Algorithm = hmacPrefix + "-" + blake2b_384String
	HMAC_BLAKE2B_512 Algorithm = hmacPrefix + "-" + blake2b_512String
	BLAKE2S_256      Algorithm = blake2s_256String
	BLAKE2B_256      Algorithm = blake2b_256String
	BLAKE2B_384      Algorithm = blake2b_384String
	BLAKE2B_512      Algorithm = blake2b_512String
	// RSA-based algorithms.
	RSA_SHA1   Algorithm = rsaPrefix + "-" + sha1String
	RSA_SHA224 Algorithm = rsaPrefix + "-" + sha224String
	// RSA_SHA256 is the default algorithm.
	RSA_SHA256    Algorithm = rsaPrefix + "-" + sha256String
	RSA_SHA384    Algorithm = rsaPrefix + "-" + sha384String
	RSA_SHA512    Algorithm = rsaPrefix + "-" + sha512String
	RSA_RIPEMD160 Algorithm = rsaPrefix + "-" + ripemd160String
	// ECDSA algorithms
	ECDSA_SHA224    Algorithm = ecdsaPrefix + "-" + sha224String
	ECDSA_SHA256    Algorithm = ecdsaPrefix + "-" + sha256String
	ECDSA_SHA384    Algorithm = ecdsaPrefix + "-" + sha384String
	ECDSA_SHA512    Algorithm = ecdsaPrefix + "-" + sha512String
	ECDSA_RIPEMD160 Algorithm = ecdsaPrefix + "-" + ripemd160String
	// ED25519 algorithms
	// can only be SHA512
	ED25519 Algorithm = ed25519Prefix

	// Just because you can glue things together, doesn't mean they will
	// work. The following options are not supported.
	rsa_SHA3_224    Algorithm = rsaPrefix + "-" + sha3_224String
	rsa_SHA3_256    Algorithm = rsaPrefix + "-" + sha3_256String
	rsa_SHA3_384    Algorithm = rsaPrefix + "-" + sha3_384String
	rsa_SHA3_512    Algorithm = rsaPrefix + "-" + sha3_512String
	rsa_SHA512_224  Algorithm = rsaPrefix + "-" + sha512_224String
	rsa_SHA512_256  Algorithm = rsaPrefix + "-" + sha512_256String
	rsa_BLAKE2S_256 Algorithm = rsaPrefix + "-" + blake2s_256String
	rsa_BLAKE2B_256 Algorithm = rsaPrefix + "-" + blake2b_256String
	rsa_BLAKE2B_384 Algorithm = rsaPrefix + "-" + blake2b_384String
	rsa_BLAKE2B_512 Algorithm = rsaPrefix + "-" + blake2b_512String
)

func getSSHAlgorithm(pkType string) Algorithm {
	switch {
	case strings.HasPrefix(pkType, sshPrefix+"-"+ed25519Prefix):
		return ED25519
	case strings.HasPrefix(pkType, sshPrefix+"-"+rsaPrefix):
		return RSA_SHA1
	}

	return ""
}

// Verifier verifies HTTP Signatures.
//
// It will determine which of the supported headers has the parameters
// that define the signature.
//
// Verifiers are not safe to use between multiple goroutines.
//
// Note that verification ignores the deprecated 'algorithm' parameter.

func newSSHSigner(sshSigner ssh.Signer, algo Algorithm, dAlgo DigestAlgorithm, headers []string, scheme SignatureScheme, expiresIn int64) (SSHSigner, error) {
	var expires, created int64 = 0, 0

	if expiresIn != 0 {
		created = time.Now().Unix()
		expires = created + expiresIn
	}

	s, err := signerFromSSHSigner(sshSigner, string(algo))
	if err != nil {
		return nil, fmt.Errorf("no crypto implementation available for ssh algo %q", algo)
	}

	a := &sshSignerAsymmetric{
		signerAsymmetric: &signerAsymmetric{
			signer:          s,
			digestAlgorithm: dAlgo,
			headers:         headers,
			scheme:          scheme,
			prefix:          scheme.authScheme(),
			created:         created,
			expires:         expires,
		},
	}

	return a, nil
}

func newSigner(alg Algorithm, dAlgo DigestAlgorithm, headers []string, scheme SignatureScheme, expiresIn int64) (Signer, error) {

	var expires, created int64 = 0, 0
	if expiresIn != 0 {
		created = time.Now().Unix()
		expires = created + expiresIn
	}

	s, err := signerFromString(string(alg))
	if err == nil {
		a := &signerAsymmetric{
			signer:          s,
			digestAlgorithm: dAlgo,
			headers:         headers,
			scheme:          scheme,
			prefix:          scheme.authScheme(),
			created:         created,
			expires:         expires,
		}
		return a, nil
	}
	m, err := macerFromString(string(alg))
	if err != nil {
		return nil, fmt.Errorf("no crypto implementation available for %q", alg)
	}
	c := &signerSymmetric{
		signer:       m,
		dAlgo:        dAlgo,
		headers:      headers,
		targetHeader: scheme,
		prefix:       scheme.authScheme(),
		created:      created,
		expires:      expires,
	}
	return c, nil
}
