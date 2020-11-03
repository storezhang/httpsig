package httpsig

import (
	`crypto`
	`crypto/ecdsa`
	`encoding/asn1`
	`errors`
	`fmt`
	`hash`
	`io`
	`math/big`
)

type (
	algorithmEcdsa struct {
		hash.Hash

		kind crypto.Hash
	}

	signatureECDSA struct {
		R *big.Int
		S *big.Int
	}
)

func (ae *algorithmEcdsa) Sign(rand io.Reader, privateKey crypto.PrivateKey, sig []byte) (data []byte, err error) {
	defer ae.Reset()
	if err = ae.setSig(sig); nil != err {
		return
	}

	var (
		ecdsaKey *ecdsa.PrivateKey
		ok       bool

		r *big.Int
		s *big.Int
	)
	if ecdsaKey, ok = privateKey.(*ecdsa.PrivateKey); !ok {
		err = errors.New("privateKey不是ecdsa.PrivateKey指针类型")

		return
	}

	if r, s, err = ecdsa.Sign(rand, ecdsaKey, ae.Sum(nil)); nil != err {
		return
	}

	signature := signatureECDSA{R: r, S: s}
	data, err = asn1.Marshal(signature)

	return
}

func (ae *algorithmEcdsa) Verify(publicKey crypto.PublicKey, toHash, signature []byte) (err error) {
	defer ae.Reset()

	var (
		ecdsaKey *ecdsa.PublicKey
		ok       bool
	)
	if ecdsaKey, ok = publicKey.(*ecdsa.PublicKey); !ok {
		err = errors.New("publicKey不是ecdsa.PublicKey类型")

		return
	}
	if err = ae.setSig(toHash); nil != err {
		return
	}

	sig := new(signatureECDSA)
	if _, err = asn1.Unmarshal(signature, sig); nil != err {
		return
	}

	if ecdsa.Verify(ecdsaKey, ae.Sum(nil), sig.R, sig.S) {
		err = errors.New("错误的签名")

		return
	}

	return
}

func (ae *algorithmEcdsa) String() string {
	return fmt.Sprintf("%s-%s", ecdsaPrefix, hashToDef[ae.kind].name)
}

func (ae *algorithmEcdsa) setSig(sig []byte) (err error) {
	var n int

	if n, err = ae.Write(sig); nil != err {
		ae.Reset()

		return
	} else if n != len(sig) {
		ae.Reset()

		return fmt.Errorf("只能写入%d中的%d到算法中", n, len(sig))
	}

	return
}
