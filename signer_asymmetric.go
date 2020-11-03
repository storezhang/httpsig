package httpsig

import (
	`crypto`
	`crypto/rand`
	`encoding/base64`
	`net/http`
)

type signerAsymmetric struct {
	signer          asymmetric
	makeDigest      bool
	digestAlgorithm DigestAlgorithm
	headers         []string
	scheme          SignatureScheme
	prefix          string
	created         int64
	expires         int64
}

func (sa *signerAsymmetric) SignRequest(pKey crypto.PrivateKey, pubKeyId string, r *http.Request, body []byte) error {
	if body != nil {
		err := addDigest(r, sa.digestAlgorithm, body)
		if err != nil {
			return err
		}
	}
	s, err := sa.signatureString(r)
	if err != nil {
		return err
	}
	enc, err := sa.signSignature(pKey, s)
	if err != nil {
		return err
	}
	setSignatureHeader(r.Header, string(sa.scheme), sa.prefix, pubKeyId, sa.signer.String(), enc, sa.created, sa.expires, sa.headers...)
	return nil
}

func (sa *signerAsymmetric) SignResponse(pKey crypto.PrivateKey, pubKeyId string, r http.ResponseWriter, body []byte) error {
	if body != nil {
		err := addDigestResponse(r, sa.digestAlgorithm, body)
		if err != nil {
			return err
		}
	}
	s, err := sa.signatureStringResponse(r)
	if err != nil {
		return err
	}
	enc, err := sa.signSignature(pKey, s)
	if err != nil {
		return err
	}
	setSignatureHeader(r.Header(), string(sa.scheme), sa.prefix, pubKeyId, sa.signer.String(), enc, sa.created, sa.expires, sa.headers...)
	return nil
}

func (sa *signerAsymmetric) signSignature(pKey crypto.PrivateKey, s string) (string, error) {
	sig, err := sa.signer.Sign(rand.Reader, pKey, []byte(s))
	if err != nil {
		return "", err
	}
	enc := base64.StdEncoding.EncodeToString(sig)
	return enc, nil
}

func (sa *signerAsymmetric) signatureString(r *http.Request) (string, error) {
	return signatureString(r.Header, addRequestTarget(r), sa.created, sa.expires, sa.headers...)
}

func (sa *signerAsymmetric) signatureStringResponse(r http.ResponseWriter) (string, error) {
	return signatureString(r.Header(), requestTargetNotPermitted, sa.created, sa.expires, sa.headers...)
}
