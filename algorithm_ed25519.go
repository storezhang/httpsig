package httpsig

import (
	`crypto`
	`errors`
	`fmt`
	`io`

	`golang.org/x/crypto/ed25519`
	`golang.org/x/crypto/ssh`
)

type algorithmEd25519 struct {
	sshSigner ssh.Signer
}

func (ae *algorithmEd25519) Sign(rand io.Reader, privateKey crypto.PrivateKey, sig []byte) (data []byte, err error) {
	if nil != ae.sshSigner {
		var signature *ssh.Signature
		if signature, err = ae.sshSigner.Sign(rand, sig); nil != err {
			return
		}

		data = signature.Blob

		return
	}

	var (
		ed25519Key ed25519.PrivateKey
		ok         bool
	)
	if ed25519Key, ok = privateKey.(ed25519.PrivateKey); !ok {
		err = errors.New("privateKey不是ed25519.PrivateKey类型")

		return
	}
	data = ed25519.Sign(ed25519Key, sig)

	return
}

func (ae *algorithmEd25519) Verify(publicKey crypto.PublicKey, toHash []byte, signature []byte) (err error) {
	var (
		ed25519K ed25519.PublicKey
		ok       bool
	)

	if ed25519K, ok = publicKey.(ed25519.PublicKey); !ok {
		err = errors.New("publicKey不是ed25519.PublicKey类型")

		return
	}

	if !ed25519.Verify(ed25519K, toHash, signature) {
		err = errors.New("错误的签名")

		return
	}

	return
}

func (ae *algorithmEd25519) String() string {
	return fmt.Sprintf("%asymmetricSigner", ed25519Prefix)
}
