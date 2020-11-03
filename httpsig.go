package httpsig

import (
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Algorithm 算法
type Algorithm string

const (
	// MAC类型算法
	HMAC_SHA224      Algorithm = hmacPrefix + "-" + sha224String
	HMAC_SHA256      Algorithm = hmacPrefix + "-" + sha256String
	HMAC_SHA384      Algorithm = hmacPrefix + "-" + sha384String
	HMAC_SHA512      Algorithm = hmacPrefix + "-" + sha512String
	HMAC_RIPEMD160   Algorithm = hmacPrefix + "-" + ripemd160String
	HMAC_SHA3_224    Algorithm = hmacPrefix + "-" + sha3With224String
	HMAC_SHA3_256    Algorithm = hmacPrefix + "-" + sha3With256String
	HMAC_SHA3_384    Algorithm = hmacPrefix + "-" + sha3With384String
	HMAC_SHA3_512    Algorithm = hmacPrefix + "-" + sha3With512String
	HMAC_SHA512_224  Algorithm = hmacPrefix + "-" + sha512With224String
	HMAC_SHA512_256  Algorithm = hmacPrefix + "-" + sha512With256String
	HMAC_BLAKE2S_256 Algorithm = hmacPrefix + "-" + blake2sWith256String
	HMAC_BLAKE2B_256 Algorithm = hmacPrefix + "-" + blake2bWith256String
	HMAC_BLAKE2B_384 Algorithm = hmacPrefix + "-" + blake2bWith384String
	HMAC_BLAKE2B_512 Algorithm = hmacPrefix + "-" + blake2bWith512String
	BLAKE2S_256      Algorithm = blake2sWith256String
	BLAKE2B_256      Algorithm = blake2bWith256String
	BLAKE2B_384      Algorithm = blake2bWith384String
	BLAKE2B_512      Algorithm = blake2bWith512String
	// RSA类型算法
	RSA_SHA1   Algorithm = rsaPrefix + "-" + sha1String
	RSA_SHA224 Algorithm = rsaPrefix + "-" + sha224String
	// RSA_SHA256 is the default algorithm.
	RSA_SHA256    Algorithm = rsaPrefix + "-" + sha256String
	RSA_SHA384    Algorithm = rsaPrefix + "-" + sha384String
	RSA_SHA512    Algorithm = rsaPrefix + "-" + sha512String
	RSA_RIPEMD160 Algorithm = rsaPrefix + "-" + ripemd160String
	// ECDSA类型算法
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
	rsa_SHA3_224    Algorithm = rsaPrefix + "-" + sha3With224String
	rsa_SHA3_256    Algorithm = rsaPrefix + "-" + sha3With256String
	rsa_SHA3_384    Algorithm = rsaPrefix + "-" + sha3With384String
	rsa_SHA3_512    Algorithm = rsaPrefix + "-" + sha3With512String
	rsa_SHA512_224  Algorithm = rsaPrefix + "-" + sha512With224String
	rsa_SHA512_256  Algorithm = rsaPrefix + "-" + sha512With256String
	rsa_BLAKE2S_256 Algorithm = rsaPrefix + "-" + blake2sWith256String
	rsa_BLAKE2B_256 Algorithm = rsaPrefix + "-" + blake2bWith256String
	rsa_BLAKE2B_384 Algorithm = rsaPrefix + "-" + blake2bWith384String
	rsa_BLAKE2B_512 Algorithm = rsaPrefix + "-" + blake2bWith512String
)

func getSSHAlgorithm(pkType string) (algorithm Algorithm) {
	switch {
	case strings.HasPrefix(pkType, sshPrefix+"-"+ed25519Prefix):
		algorithm = ED25519
	case strings.HasPrefix(pkType, sshPrefix+"-"+rsaPrefix):
		algorithm = RSA_SHA1
	default:
		algorithm = ""
	}

	return
}

func newSSHSigner(
	ssh ssh.Signer,
	alg Algorithm,
	digest DigestAlgorithm,
	headers []string,
	scheme SignatureScheme,
	expiresIn int64,
) (signer SSHSigner, err error) {
	var (
		expires int64 = 0
		created int64 = 0
	)

	if 0 != expiresIn {
		created = time.Now().Unix()
		expires = created + expiresIn
	}

	var asymmetric asymmetric
	if asymmetric, err = asymmetricFromSSHSigner(ssh, string(alg)); nil != err {
		return
	}

	signer = &sshSignerAsymmetric{
		signerAsymmetric: &signerAsymmetric{
			signer:          asymmetric,
			digestAlgorithm: digest,
			headers:         headers,
			scheme:          scheme,
			prefix:          scheme.authScheme(),
			created:         created,
			expires:         expires,
		},
	}

	return
}

func newSigner(
	alg Algorithm,
	digest DigestAlgorithm,
	headers []string,
	scheme SignatureScheme,
	expiresIn int64,
) (signer Signer, err error) {
	var (
		expires int64 = 0
		created int64 = 0
	)

	if 0 != expiresIn {
		created = time.Now().Unix()
		expires = created + expiresIn
	}

	var asymmetric asymmetric
	if asymmetric, err = asymmetricFromString(string(alg)); nil == err {
		signer = &signerAsymmetric{
			signer:          asymmetric,
			digestAlgorithm: digest,
			headers:         headers,
			scheme:          scheme,
			prefix:          scheme.authScheme(),
			created:         created,
			expires:         expires,
		}

		return
	}

	var symmetric symmetric
	if symmetric, err = symmetricFromString(string(alg)); nil != err {
		return
	}

	signer = &signerSymmetric{
		signer:       symmetric,
		dAlgo:        digest,
		headers:      headers,
		targetHeader: scheme,
		prefix:       scheme.authScheme(),
		created:      created,
		expires:      expires,
	}

	return
}
