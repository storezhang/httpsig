package httpsig

import (
	`crypto`
	`crypto/subtle`
	`fmt`
	`hash`
)

type algorithmBlakeMac struct {
	fn   func(key []byte) (hash.Hash, error)
	kind crypto.Hash
}

func (abm *algorithmBlakeMac) Sign(sig []byte, key []byte) (data []byte, err error) {
	var h hash.Hash

	if h, err = abm.fn(key); nil != err {
		return
	}
	if err = setSig(h, sig); nil != err {
		return
	}
	data = h.Sum(nil)

	return
}

func (abm *algorithmBlakeMac) Equal(sig []byte, actualMac []byte, key []byte) (equal bool, err error) {
	var h hash.Hash

	if h, err = abm.fn(key); nil != err {
		return
	}
	defer h.Reset()

	if err = setSig(h, sig); nil != err {
		return
	}
	expected := h.Sum(nil)
	equal = 1 == subtle.ConstantTimeCompare(actualMac, expected)

	return
}

func (abm *algorithmBlakeMac) String() string {
	return fmt.Sprintf("%asymmetricSigner", hashToDef[abm.kind].name)
}
