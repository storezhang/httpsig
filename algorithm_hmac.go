package httpsig

import (
	`crypto`
	`crypto/hmac`
	`fmt`
	`hash`
)

type algorithmHmac struct {
	fn   func(key []byte) (hash.Hash, error)
	kind crypto.Hash
}

func (ah *algorithmHmac) Sign(sig []byte, key []byte) (data []byte, err error) {
	var h hash.Hash

	if h, err = ah.fn(key); nil != err {
		return
	}
	defer h.Reset()

	if err = setSig(h, sig); nil != err {
		return
	}
	data = h.Sum(nil)

	return
}

func (ah *algorithmHmac) Equal(sig, actualMAC, key []byte) (equal bool, err error) {
	var h hash.Hash

	if h, err = ah.fn(key); nil != err {
		return
	}
	defer h.Reset()

	if err = setSig(h, sig); nil != err {
		return
	}
	expected := h.Sum(nil)
	equal = hmac.Equal(actualMAC, expected)

	return
}

func (ah *algorithmHmac) String() string {
	return fmt.Sprintf("%s-%s", hmacPrefix, hashToDef[ah.kind].name)
}
