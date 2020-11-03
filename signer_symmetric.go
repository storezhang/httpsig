package httpsig

import (
	`crypto`
	`encoding/base64`
	`fmt`
	`net/http`
)

type signerSymmetric struct {
	signer       symmetric
	makeDigest   bool
	dAlgo        DigestAlgorithm
	headers      []string
	targetHeader SignatureScheme
	prefix       string
	created      int64
	expires      int64
}

func (ss *signerSymmetric) SignRequest(privateKey crypto.PrivateKey, keyId string, req *http.Request, body []byte) (err error) {
	if body != nil {
		err := addDigest(req, ss.dAlgo, body)
		if err != nil {
			return err
		}
	}
	s, err := ss.signatureString(req)
	if err != nil {
		return err
	}
	enc, err := ss.signSignature(privateKey, s)
	if err != nil {
		return err
	}
	setSignatureHeader(req.Header, string(ss.targetHeader), ss.prefix, keyId, ss.signer.String(), enc, ss.created, ss.expires, ss.headers...)
	return nil
}

func (ss *signerSymmetric) SignResponse(pKey crypto.PrivateKey, pubKeyId string, r http.ResponseWriter, body []byte) error {
	if body != nil {
		err := addDigestResponse(r, ss.dAlgo, body)
		if err != nil {
			return err
		}
	}
	s, err := ss.signatureStringResponse(r)
	if err != nil {
		return err
	}
	enc, err := ss.signSignature(pKey, s)
	if err != nil {
		return err
	}
	setSignatureHeader(r.Header(), string(ss.targetHeader), ss.prefix, pubKeyId, ss.signer.String(), enc, ss.created, ss.expires, ss.headers...)
	return nil
}

func (ss *signerSymmetric) signSignature(pKey crypto.PrivateKey, s string) (string, error) {
	pKeyBytes, ok := pKey.([]byte)
	if !ok {
		return "", fmt.Errorf("private key for MAC signing must be of type []byte")
	}
	sig, err := ss.signer.Sign([]byte(s), pKeyBytes)
	if err != nil {
		return "", err
	}
	enc := base64.StdEncoding.EncodeToString(sig)
	return enc, nil
}

func (ss *signerSymmetric) signatureString(r *http.Request) (string, error) {
	return signatureString(r.Header, addRequestTarget(r), ss.created, ss.expires, ss.headers...)
}

func (ss *signerSymmetric) signatureStringResponse(r http.ResponseWriter) (string, error) {
	return signatureString(r.Header(), requestTargetNotPermitted, ss.created, ss.expires, ss.headers...)
}
