package httpsig

import (
	`crypto`
	`crypto/hmac`
	`crypto/sha1`
	`crypto/sha256`
	`crypto/sha512`
	`fmt`
	`hash`
	`io`
	`strings`

	`golang.org/x/crypto/blake2b`
	`golang.org/x/crypto/blake2s`
	`golang.org/x/crypto/ripemd160`
	`golang.org/x/crypto/sha3`
	`golang.org/x/crypto/ssh`
)

const (
	hmacPrefix        = "hmac"
	rsaPrefix         = "rsa"
	sshPrefix         = "ssh"
	ecdsaPrefix       = "ecdsa"
	ed25519Prefix     = "ed25519"
	md4String         = "md4"
	md5String         = "md5"
	sha1String        = "sha1"
	sha224String      = "sha224"
	sha256String      = "sha256"
	sha384String      = "sha384"
	sha512String      = "sha512"
	md5sha1String     = "md5sha1"
	ripemd160String   = "ripemd160"
	sha3_224String    = "sha3-224"
	sha3_256String    = "sha3-256"
	sha3_384String    = "sha3-384"
	sha3_512String    = "sha3-512"
	sha512_224String  = "sha512-224"
	sha512_256String  = "sha512-256"
	blake2s_256String = "blake2s-256"
	blake2b_256String = "blake2b-256"
	blake2b_384String = "blake2b-384"
	blake2b_512String = "blake2b-512"

	defaultAlgorithm        = RSA_SHA256
	defaultAlgorithmHashing = sha256String
)

var (
	stringToHash     map[string]crypto.Hash
	blake2Algorithms = map[crypto.Hash]bool{
		crypto.BLAKE2s_256: true,
		crypto.BLAKE2b_256: true,
		crypto.BLAKE2b_384: true,
		crypto.BLAKE2b_512: true,
	}
	hashToDef = map[crypto.Hash]struct {
		name string
		new  func(key []byte) (hash.Hash, error)
	}{

		crypto.MD4:         {md4String, func(key []byte) (hash.Hash, error) { return nil, nil }},
		crypto.MD5:         {md5String, func(key []byte) (hash.Hash, error) { return nil, nil }},
		crypto.SHA1:        {sha1String, func(key []byte) (hash.Hash, error) { return sha1.New(), nil }},
		crypto.SHA224:      {sha224String, func(key []byte) (hash.Hash, error) { return sha256.New224(), nil }},
		crypto.SHA256:      {sha256String, func(key []byte) (hash.Hash, error) { return sha256.New(), nil }},
		crypto.SHA384:      {sha384String, func(key []byte) (hash.Hash, error) { return sha512.New384(), nil }},
		crypto.SHA512:      {sha512String, func(key []byte) (hash.Hash, error) { return sha512.New(), nil }},
		crypto.MD5SHA1:     {md5sha1String, func(key []byte) (hash.Hash, error) { return nil, nil }},
		crypto.RIPEMD160:   {ripemd160String, func(key []byte) (hash.Hash, error) { return ripemd160.New(), nil }},
		crypto.SHA3_224:    {sha3_224String, func(key []byte) (hash.Hash, error) { return sha3.New224(), nil }},
		crypto.SHA3_256:    {sha3_256String, func(key []byte) (hash.Hash, error) { return sha3.New256(), nil }},
		crypto.SHA3_384:    {sha3_384String, func(key []byte) (hash.Hash, error) { return sha3.New384(), nil }},
		crypto.SHA3_512:    {sha3_512String, func(key []byte) (hash.Hash, error) { return sha3.New512(), nil }},
		crypto.SHA512_224:  {sha512_224String, func(key []byte) (hash.Hash, error) { return sha512.New512_224(), nil }},
		crypto.SHA512_256:  {sha512_256String, func(key []byte) (hash.Hash, error) { return sha512.New512_256(), nil }},
		crypto.BLAKE2s_256: {blake2s_256String, func(key []byte) (hash.Hash, error) { return blake2s.New256(key) }},
		crypto.BLAKE2b_256: {blake2b_256String, func(key []byte) (hash.Hash, error) { return blake2b.New256(key) }},
		crypto.BLAKE2b_384: {blake2b_384String, func(key []byte) (hash.Hash, error) { return blake2b.New384(key) }},
		crypto.BLAKE2b_512: {blake2b_512String, func(key []byte) (hash.Hash, error) { return blake2b.New512(key) }},
	}
)

func init() {
	stringToHash = make(map[string]crypto.Hash, len(hashToDef))
	for k, v := range hashToDef {
		stringToHash[v.name] = k
	}

	if ok, err := isAvailable(defaultAlgorithmHashing); err != nil {
		panic(err)
	} else if !ok {
		panic(fmt.Sprintf("没有实现的算法：%q", defaultAlgorithm))
	}
}

// asymmetricSigner 非对称加密签名接口
type asymmetricSigner interface {
	Sign(rand io.Reader, privateKey crypto.PrivateKey, signature []byte) ([]byte, error)
	Verify(publicKey crypto.PublicKey, toHash []byte, signature []byte) (err error)
	String() string
}

// symmetricSigner 对称加密签名接口
type symmetricSigner interface {
	Sign(sig, key []byte) ([]byte, error)
	Equal(sig, actualMAC, key []byte) (bool, error)
	String() string
}

func setSig(a hash.Hash, b []byte) error {
	n, err := a.Write(b)
	if err != nil {
		a.Reset()
		return err
	} else if n != len(b) {
		a.Reset()
		return fmt.Errorf("could only write %d of %d bytes of signature to hash", n, len(b))
	}
	return nil
}

func isForbiddenHash(hash crypto.Hash) (forbidden bool) {
	switch hash {
	case crypto.MD4:
		fallthrough
	case crypto.MD5:
		fallthrough
	case crypto.MD5SHA1:
		forbidden = true
	}

	return
}

func isAvailable(alg string) (available bool, err error) {
	var (
		cryptoHash crypto.Hash
		ok         bool
	)
	if cryptoHash, ok = stringToHash[alg]; !ok {
		err = fmt.Errorf("没有匹配的算法：%q", alg)

		return
	}

	if isForbiddenHash(cryptoHash) {
		err = fmt.Errorf("算法被禁止使用：%q", alg)
	}

	available = cryptoHash.Available()

	return
}

func newAlgorithmConstructor(alg string) (fn func(k []byte) (hash.Hash, error), cryptoHash crypto.Hash, err error) {
	var ok bool

	if cryptoHash, ok = stringToHash[alg]; !ok {
		err = fmt.Errorf("不支持的算法：%q", alg)

		return
	}

	if isForbiddenHash(cryptoHash) {
		err = fmt.Errorf("被禁止使用的算法：%q", alg)

		return
	}

	algoDef, ok := hashToDef[cryptoHash]
	if !ok {
		err = fmt.Errorf("have crypto.Hash %v but no definition", cryptoHash)
		return
	}
	fn = func(key []byte) (hash.Hash, error) {
		h, err := algoDef.new(key)
		if err != nil {
			return nil, err
		}
		return h, nil
	}

	return
}

func newAlgorithm(algo string, key []byte) (hash.Hash, crypto.Hash, error) {
	fn, c, err := newAlgorithmConstructor(algo)
	if err != nil {
		return nil, c, err
	}
	h, err := fn(key)
	return h, c, err
}

func signerFromSSHSigner(sshSigner ssh.Signer, s string) (asymmetricSigner, error) {
	switch {
	case strings.HasPrefix(s, rsaPrefix):
		return &algorithmRsa{
			sshSigner: sshSigner,
		}, nil
	case strings.HasPrefix(s, ed25519Prefix):
		return &algorithmEd25519{
			sshSigner: sshSigner,
		}, nil
	default:
		return nil, fmt.Errorf("no asymmetricSigner matching %q", s)
	}
}

// signerFromString is an internally public method constructor
func signerFromString(s string) (asymmetricSigner, error) {
	s = strings.ToLower(s)
	isEcdsa := false
	isEd25519 := false
	var algo = ""
	if strings.HasPrefix(s, ecdsaPrefix) {
		algo = strings.TrimPrefix(s, ecdsaPrefix+"-")
		isEcdsa = true
	} else if strings.HasPrefix(s, rsaPrefix) {
		algo = strings.TrimPrefix(s, rsaPrefix+"-")
	} else if strings.HasPrefix(s, ed25519Prefix) {
		isEd25519 = true
		algo = "sha512"
	} else {
		return nil, fmt.Errorf("no asymmetricSigner matching %q", s)
	}
	hash, cHash, err := newAlgorithm(algo, nil)
	if err != nil {
		return nil, err
	}
	if isEd25519 {
		return &algorithmEd25519{}, nil
	}
	if isEcdsa {
		return &algorithmEcdsa{
			Hash: hash,
			kind: cHash,
		}, nil
	}
	return &algorithmRsa{
		Hash: hash,
		kind: cHash,
	}, nil
}

// macerFromString is an internally public method constructor
func macerFromString(s string) (symmetricSigner, error) {
	s = strings.ToLower(s)
	if strings.HasPrefix(s, hmacPrefix) {
		algo := strings.TrimPrefix(s, hmacPrefix+"-")
		hashFn, cHash, err := newAlgorithmConstructor(algo)
		if err != nil {
			return nil, err
		}
		// Ensure below does not panic
		_, err = hashFn(nil)
		if err != nil {
			return nil, err
		}
		return &algorithmHmac{
			fn: func(key []byte) (hash.Hash, error) {
				return hmac.New(func() hash.Hash {
					h, e := hashFn(nil)
					if e != nil {
						panic(e)
					}
					return h
				}, key), nil
			},
			kind: cHash,
		}, nil
	} else if bl, ok := stringToHash[s]; ok && blake2Algorithms[bl] {
		hashFn, cHash, err := newAlgorithmConstructor(s)
		if err != nil {
			return nil, err
		}
		return &algorithmBlakeMac{
			fn:   hashFn,
			kind: cHash,
		}, nil
	} else {
		return nil, fmt.Errorf("no MACer matching %q", s)
	}
}
