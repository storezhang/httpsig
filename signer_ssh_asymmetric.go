package httpsig

import (
	`net/http`
)

type sshSignerAsymmetric struct {
	*signerAsymmetric
}

func (a *sshSignerAsymmetric) SignRequest(pubKeyId string, r *http.Request, body []byte) error {
	return a.signerAsymmetric.SignRequest(nil, pubKeyId, r, body)
}

func (a *sshSignerAsymmetric) SignResponse(pubKeyId string, r http.ResponseWriter, body []byte) error {
	return a.signerAsymmetric.SignResponse(nil, pubKeyId, r, body)
}
