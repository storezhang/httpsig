package httpsig

import (
	`crypto`
	`io`
)

// asymmetric 非对称加密签名接口
type asymmetric interface {
	Sign(rand io.Reader, privateKey crypto.PrivateKey, signature []byte) ([]byte, error)
	Verify(publicKey crypto.PublicKey, toHash []byte, signature []byte) (err error)
	String() string
}
