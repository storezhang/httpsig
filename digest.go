package httpsig

import (
	"crypto"
	"encoding/base64"
	"fmt"
	"hash"
	"net/http"
	"strings"
)

// DigestAlgorithm 算法摘要
type DigestAlgorithm string

const (
	// DigestSha256 SHA 256算法
	DigestSha256 DigestAlgorithm = "SHA-256"
	// DigestSha512 SHA 512算法
	DigestSha512 DigestAlgorithm = "SHA-512"

	digestHeader    = "Digest"
	digestDelimiter = "="
)

var defaultDigest = map[DigestAlgorithm]crypto.Hash{
	DigestSha256: crypto.SHA256,
	DigestSha512: crypto.SHA512,
}

func getHash(da DigestAlgorithm) (hash hash.Hash, algorithm DigestAlgorithm, err error) {
	upper := DigestAlgorithm(strings.ToUpper(string(da)))
	sha, ok := defaultDigest[upper]
	if !ok {
		err = fmt.Errorf("没有实现的算法：%s", da)

		return
	}
	if !sha.Available() {
		err = fmt.Errorf("没有实现的算法接要：%s", da)

		return
	}
	hash = sha.New()
	algorithm = upper

	return
}

func addDigest(req *http.Request, algorithm DigestAlgorithm, b []byte) (err error) {
	_, ok := req.Header[digestHeader]
	if ok {
		err = fmt.Errorf("没有找到请求头：%s", digestHeader)

		return
	}

	var (
		h  hash.Hash
		da DigestAlgorithm
	)

	if h, da, err = getHash(algorithm); nil != err {
		return
	}

	h.Write(b)
	sum := h.Sum(nil)
	req.Header.Add(digestHeader, fmt.Sprintf(
		"%s%s%s",
		da,
		digestDelimiter,
		base64.StdEncoding.EncodeToString(sum[:]),
	))

	return
}

func addDigestResponse(rsp http.ResponseWriter, algorithm DigestAlgorithm, b []byte) (err error) {
	_, ok := rsp.Header()[digestHeader]
	if ok {
		err = fmt.Errorf("无法写入响应头：%s", digestHeader)

		return
	}

	var (
		h  hash.Hash
		da DigestAlgorithm
	)

	if h, da, err = getHash(algorithm); nil != err {
		return
	}

	h.Write(b)
	sum := h.Sum(nil)
	rsp.Header().Add(digestHeader, fmt.Sprintf(
		"%s%s%s",
		da,
		digestDelimiter,
		base64.StdEncoding.EncodeToString(sum[:]),
	))

	return
}
