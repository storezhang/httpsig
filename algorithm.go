package httpsig

import (
	`crypto`
	`crypto/hmac`
	`crypto/sha1`
	`crypto/sha256`
	`crypto/sha512`
	`fmt`
	`hash`
	`strings`

	`golang.org/x/crypto/blake2b`
	`golang.org/x/crypto/blake2s`
	`golang.org/x/crypto/ripemd160`
	`golang.org/x/crypto/sha3`
	`golang.org/x/crypto/ssh`
)

const (
	hmacPrefix           = "hmac"
	rsaPrefix            = "rsa"
	sshPrefix            = "ssh"
	ecdsaPrefix          = "ecdsa"
	ed25519Prefix        = "ed25519"
	md4String            = "md4"
	md5String            = "md5"
	sha1String           = "sha1"
	sha224String         = "sha224"
	sha256String         = "sha256"
	sha384String         = "sha384"
	sha512String         = "sha512"
	md5sha1String        = "md5sha1"
	ripemd160String      = "ripemd160"
	sha3With224String    = "sha3-224"
	sha3With256String    = "sha3-256"
	sha3With384String    = "sha3-384"
	sha3With512String    = "sha3-512"
	sha512With224String  = "sha512-224"
	sha512With256String  = "sha512-256"
	blake2sWith256String = "blake2s-256"
	blake2bWith256String = "blake2b-256"
	blake2bWith384String = "blake2b-384"
	blake2bWith512String = "blake2b-512"

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
	hashToDef = map[crypto.Hash]algorithm{
		crypto.MD4: {
			name:    md4String,
			newFunc: func(key []byte) (hash.Hash, error) { return nil, nil },
		},
		crypto.MD5: {
			name:    md5String,
			newFunc: func(key []byte) (hash.Hash, error) { return nil, nil },
		},
		crypto.SHA1: {
			name:    sha1String,
			newFunc: func(key []byte) (hash.Hash, error) { return sha1.New(), nil },
		},
		crypto.SHA224:      {sha224String, func(key []byte) (hash.Hash, error) { return sha256.New224(), nil }},
		crypto.SHA256:      {sha256String, func(key []byte) (hash.Hash, error) { return sha256.New(), nil }},
		crypto.SHA384:      {sha384String, func(key []byte) (hash.Hash, error) { return sha512.New384(), nil }},
		crypto.SHA512:      {sha512String, func(key []byte) (hash.Hash, error) { return sha512.New(), nil }},
		crypto.MD5SHA1:     {md5sha1String, func(key []byte) (hash.Hash, error) { return nil, nil }},
		crypto.RIPEMD160:   {ripemd160String, func(key []byte) (hash.Hash, error) { return ripemd160.New(), nil }},
		crypto.SHA3_224:    {sha3With224String, func(key []byte) (hash.Hash, error) { return sha3.New224(), nil }},
		crypto.SHA3_256:    {sha3With256String, func(key []byte) (hash.Hash, error) { return sha3.New256(), nil }},
		crypto.SHA3_384:    {sha3With384String, func(key []byte) (hash.Hash, error) { return sha3.New384(), nil }},
		crypto.SHA3_512:    {sha3With512String, func(key []byte) (hash.Hash, error) { return sha3.New512(), nil }},
		crypto.SHA512_224:  {sha512With224String, func(key []byte) (hash.Hash, error) { return sha512.New512_224(), nil }},
		crypto.SHA512_256:  {sha512With256String, func(key []byte) (hash.Hash, error) { return sha512.New512_256(), nil }},
		crypto.BLAKE2s_256: {blake2sWith256String, func(key []byte) (hash.Hash, error) { return blake2s.New256(key) }},
		crypto.BLAKE2b_256: {blake2bWith256String, func(key []byte) (hash.Hash, error) { return blake2b.New256(key) }},
		crypto.BLAKE2b_384: {blake2bWith384String, func(key []byte) (hash.Hash, error) { return blake2b.New384(key) }},
		crypto.BLAKE2b_512: {blake2bWith512String, func(key []byte) (hash.Hash, error) { return blake2b.New512(key) }},
	}
)

type (
	algorithmNewFunc func(key []byte) (hash.Hash, error)

	algorithm struct {
		name    string
		newFunc algorithmNewFunc
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

func newAlgorithmConstructor(alg string) (fn algorithmNewFunc, cryptoHash crypto.Hash, err error) {
	var ok bool

	if cryptoHash, ok = stringToHash[alg]; !ok {
		err = fmt.Errorf("不支持的算法：%q", alg)

		return
	}

	if isForbiddenHash(cryptoHash) {
		err = fmt.Errorf("被禁止使用的算法：%q", alg)

		return
	}

	var algorithm algorithm
	if algorithm, ok = hashToDef[cryptoHash]; !ok {
		err = fmt.Errorf("未被定义的Hash算法：%v", cryptoHash)

		return
	}

	fn = func(key []byte) (hash.Hash, error) {
		return algorithm.newFunc(key)
	}

	return
}

func newAlgorithm(alg string, key []byte) (h hash.Hash, cryptoHash crypto.Hash, err error) {
	var fn algorithmNewFunc

	if fn, cryptoHash, err = newAlgorithmConstructor(alg); nil != err {
		return
	}
	h, err = fn(key)

	return
}

func asymmetricFromSSHSigner(ssh ssh.Signer, s string) (asymmetric asymmetric, err error) {
	switch {
	case strings.HasPrefix(s, rsaPrefix):
		asymmetric = &algorithmRsa{
			sshSigner: ssh,
		}
	case strings.HasPrefix(s, ed25519Prefix):
		asymmetric = &algorithmEd25519{
			sshSigner: ssh,
		}
	default:
		err = fmt.Errorf("没有匹配的非对称加密算法：%q", s)
	}

	return
}

func asymmetricFromString(in string) (asymmetric asymmetric, err error) {
	in = strings.ToLower(in)

	isEcdsa := false
	isEd25519 := false
	alg := ""
	switch {
	case strings.HasPrefix(in, ecdsaPrefix):
		alg = strings.TrimPrefix(in, ecdsaPrefix+"-")
		isEcdsa = true
	case strings.HasPrefix(in, rsaPrefix):
		alg = strings.TrimPrefix(in, rsaPrefix+"-")
	case strings.HasPrefix(in, ed25519Prefix):
		isEd25519 = true
		alg = "sha512"
	default:
		err = fmt.Errorf("没有匹配的非对称加密算法：%q", in)
	}
	if nil != err {
		return
	}

	var (
		h          hash.Hash
		cryptoHash crypto.Hash
	)

	if h, cryptoHash, err = newAlgorithm(alg, nil); nil != err {
		return
	}

	if isEd25519 {
		asymmetric = &algorithmEd25519{}
	}
	if isEcdsa {
		asymmetric = &algorithmEcdsa{
			Hash: h,
			kind: cryptoHash,
		}
	}

	asymmetric = &algorithmRsa{
		Hash: h,
		kind: cryptoHash,
	}

	return
}

func symmetricFromString(in string) (symmetric symmetric, err error) {
	in = strings.ToLower(in)

	var (
		newFunc    algorithmNewFunc
		cryptoHash crypto.Hash
	)
	if strings.HasPrefix(in, hmacPrefix) {
		alg := strings.TrimPrefix(in, hmacPrefix+"-")
		if newFunc, cryptoHash, err = newAlgorithmConstructor(alg); nil != err {
			return
		}

		// 确认不要抛异常
		if _, err = newFunc(nil); nil != err {
			return
		}
		symmetric = &algorithmHmac{
			fn: func(key []byte) (hash.Hash, error) {
				return hmac.New(func() hash.Hash {
					h, e := newFunc(nil)
					if e != nil {
						panic(e)
					}

					return h
				}, key), nil
			},
			kind: cryptoHash,
		}
	} else if bl, ok := stringToHash[in]; ok && blake2Algorithms[bl] {
		if newFunc, cryptoHash, err = newAlgorithmConstructor(in); nil != err {
			return
		}

		symmetric = &algorithmBlakeMac{
			fn:   newFunc,
			kind: cryptoHash,
		}
	} else {
		err = fmt.Errorf("没有匹配的对称加密算法%q", in)
	}

	return
}
