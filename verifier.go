package httpsig

import (
	`crypto`
	`net/http`
)

// Verifier 签名验证接口
type Verifier interface {
	// KeyId 取得签名的公钥
	KeyId() string

	// Verify 验证签名
	Verify(publicKey crypto.PublicKey, alg Algorithm) (err error)
}

const (
	hostHeader = "Host"
)

func NewVerifier(req *http.Request) (verifier Verifier, err error) {
	if _, hasHostHeader := req.Header[hostHeader]; len(req.Host) > 0 && !hasHostHeader {
		req.Header[hostHeader] = []string{req.Host}
	}

	return newVerifier(
		req.Header,
		func(header http.Header, toInclude []string, created int64, expires int64) (string, error) {
			return signatureString(header, toInclude, addRequestTarget(req), created, expires)
		},
	)
}

func NewResponseVerifier(rsp *http.Response) (Verifier, error) {
	return newVerifier(
		rsp.Header,
		func(h http.Header, toInclude []string, created int64, expires int64) (string, error) {
			return signatureString(h, toInclude, requestTargetNotPermitted, created, expires)
		},
	)
}
