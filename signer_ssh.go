package httpsig

import (
	`fmt`
	`net/http`

	`golang.org/x/crypto/ssh`
)

// SSHSigner SSH签名接口
type SSHSigner interface {
	// SignRequest 签名请求
	SignRequest(keyId string, req *http.Request, body []byte) (err error)
	// SignResponse 签名响应
	SignResponse(keyId string, rsp http.ResponseWriter, body []byte) (err error)
}

func NewSSHSigner(s ssh.Signer, dAlgo DigestAlgorithm, headers []string, scheme SignatureScheme, expiresIn int64) (SSHSigner, Algorithm, error) {
	sshAlgo := getSSHAlgorithm(s.PublicKey().Type())
	if sshAlgo == "" {
		return nil, "", fmt.Errorf("key type: %s not supported yet.", s.PublicKey().Type())
	}

	signer, err := newSSHSigner(s, sshAlgo, dAlgo, headers, scheme, expiresIn)
	if err != nil {
		return nil, "", err
	}

	return signer, sshAlgo, nil
}
