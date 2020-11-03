package httpsig

// symmetric 对称加密签名接口
type symmetric interface {
	Sign(sig, key []byte) ([]byte, error)
	Equal(sig, actualMAC, key []byte) (bool, error)
	String() string
}
