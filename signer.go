package httpsig

import (
	`crypto`
	`net/http`
)

// Signer 签名接口
type Signer interface {
	// SignRequest 签名请求
	SignRequest(privateKey crypto.PrivateKey, keyId string, req *http.Request, body []byte) (err error)
	// SignResponse 签名响应
	SignResponse(privateKey crypto.PrivateKey, keyId string, rsp http.ResponseWriter, body []byte) (err error)
}

func NewSigner(prefs []Algorithm, dAlgo DigestAlgorithm, headers []string, scheme SignatureScheme, expiresIn int64) (Signer, Algorithm, error) {
	for _, pref := range prefs {
		s, err := newSigner(pref, dAlgo, headers, scheme, expiresIn)
		if err != nil {
			continue
		}
		return s, pref, err
	}
	s, err := newSigner(defaultAlgorithm, dAlgo, headers, scheme, expiresIn)
	return s, defaultAlgorithm, err
}
