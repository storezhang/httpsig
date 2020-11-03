package httpsig

import (
	`crypto`
	`crypto/rsa`
	`errors`
	`fmt`
	`hash`
	`io`

	`golang.org/x/crypto/ssh`
)

type algorithmRsa struct {
	hash.Hash

	kind      crypto.Hash
	sshSigner ssh.Signer
}

func (ar *algorithmRsa) Sign(rand io.Reader, privateKey crypto.PrivateKey, sig []byte) (data []byte, err error) {
	if nil != ar.sshSigner {
		var signature *ssh.Signature
		if signature, err = ar.sshSigner.Sign(rand, sig); nil != err {
			return
		}

		data = signature.Blob

		return
	}
	defer ar.Reset()

	if err = ar.setSig(sig); nil != err {
		return
	}

	key, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		err = errors.New("privateKey不是rsa.PrivateKey类型")

		return
	}

	data, err = rsa.SignPKCS1v15(rand, key, ar.kind, ar.Sum(nil))

	return
}

func (ar *algorithmRsa) Verify(publicKey crypto.PublicKey, toHash []byte, signature []byte) (err error) {
	defer ar.Reset()
	if err = ar.setSig(toHash); nil != err {
		return
	}

	key, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		err = errors.New("privateKey不是rsa.PrivateKey类型")

		return
	}
	err = rsa.VerifyPKCS1v15(key, ar.kind, ar.Sum(nil), signature)

	return
}

func (ar *algorithmRsa) String() string {
	return fmt.Sprintf("%s-%s", rsaPrefix, hashToDef[ar.kind].name)
}

func (ar *algorithmRsa) setSig(sig []byte) (err error) {
	var n int

	if n, err = ar.Write(sig); nil != err {
		ar.Reset()

		return
	} else if n != len(sig) {
		ar.Reset()

		return fmt.Errorf("只能写入%d中的%d到算法中", n, len(sig))
	}

	return
}
