package httpsig

import (
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type verifier struct {
	header      http.Header
	keyId       string
	signature   string
	created     int64
	expires     int64
	headers     []string
	sigStringFn func(http.Header, []string, int64, int64) (string, error)
}

func newVerifier(
	header http.Header,
	sigStringFn func(http.Header, []string, int64, int64) (string, error),
) (v *verifier, err error) {
	var (
		scheme SignatureScheme
		value  string
	)

	if scheme, value, err = getSignatureScheme(header); nil != err {
		return
	}

	var (
		keyId     string
		signature string
		headers   []string
		created   int64
		expires   int64
	)
	if keyId, signature, headers, created, expires, err = getSignatureComponents(scheme, value); nil != err {
		return
	}

	now := time.Now().Unix()
	// 最大允许10秒内创建的签名
	if 0 != created && created-now > 10 {
		err = errors.New("签名时间不正确")

		return
	}
	if 0 != expires && now-expires > 10 {
		err = errors.New("签名已过期")

		return
	}

	v = &verifier{
		header:      header,
		keyId:       keyId,
		signature:   signature,
		created:     created,
		expires:     expires,
		headers:     headers,
		sigStringFn: sigStringFn,
	}

	return
}

func (v *verifier) KeyId() string {
	return v.keyId
}

func (v *verifier) Verify(publicKey crypto.PublicKey, alg Algorithm) (err error) {
	var signer asymmetricSigner

	if signer, err = signerFromString(string(alg)); nil != err {
		err = v.asymmVerify(signer, publicKey)

		return
	}

	m, err := macerFromString(string(alg))
	if err == nil {
		return v.macVerify(m, publicKey)
	}
	return fmt.Errorf("no crypto implementation available for %q", alg)
}

func (v *verifier) macVerify(m symmetricSigner, pKey crypto.PublicKey) error {
	key, ok := pKey.([]byte)
	if !ok {
		return fmt.Errorf("public key for MAC verifying must be of type []byte")
	}
	signature, err := v.sigStringFn(v.header, v.headers, v.created, v.expires)
	if err != nil {
		return err
	}
	actualMAC, err := base64.StdEncoding.DecodeString(v.signature)
	if err != nil {
		return err
	}
	ok, err = m.Equal([]byte(signature), actualMAC, key)
	if err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("invalid http signature")
	}
	return nil
}

func (v *verifier) asymmVerify(s asymmetricSigner, pKey crypto.PublicKey) error {
	toHash, err := v.sigStringFn(v.header, v.headers, v.created, v.expires)
	if err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(v.signature)
	if err != nil {
		return err
	}
	err = s.Verify(pKey, []byte(toHash), signature)
	if err != nil {
		return err
	}
	return nil
}

func getSignatureScheme(header http.Header) (scheme SignatureScheme, value string, err error) {
	signature := header.Get(string(Signature))
	sigHasAll := strings.Contains(signature, keyIdParameter) ||
		strings.Contains(signature, headersParameter) ||
		strings.Contains(signature, signatureParameter)

	authorization := header.Get(string(Authorization))
	authHasAll := strings.Contains(authorization, keyIdParameter) ||
		strings.Contains(authorization, headersParameter) ||
		strings.Contains(authorization, signatureParameter)

	if sigHasAll && authHasAll {
		err = fmt.Errorf("%q和%q不能同时存在", Signature, Authorization)
	} else if !sigHasAll && !authHasAll {
		err = fmt.Errorf("%q或%q必须存在一个", Signature, Authorization)
	} else if sigHasAll {
		value = signature
		scheme = Signature
	} else {
		value = authorization
		scheme = Authorization
	}

	return
}

func getSignatureComponents(scheme SignatureScheme, value string) (
	keyId string,
	sig string,
	headers []string,
	created int64,
	expires int64,
	err error,
) {
	if authScheme := scheme.authScheme(); len(authScheme) > 0 {
		value = strings.TrimPrefix(value, authScheme+prefixSeparater)
	}
	params := strings.Split(value, parameterSeparater)

	for _, param := range params {
		kv := strings.SplitN(param, parameterKVSeparater, 2)
		if len(kv) != 2 {
			err = fmt.Errorf("签名格式不正确：%signValue", kv)

			return
		}

		signKey := kv[0]
		signValue := strings.Trim(kv[1], parameterValueDelimiter)
		switch signKey {
		case keyIdParameter:
			keyId = signValue
		case createdKey:
			created, err = strconv.ParseInt(signValue, 10, 64)
			if err != nil {
				return
			}
		case expiresKey:
			expires, err = strconv.ParseInt(signValue, 10, 64)
			if err != nil {
				return
			}
		case headersParameter:
			headers = strings.Split(signValue, headerParameterValueDelimiter)
		case signatureParameter:
			sig = signValue
		}
	}

	if 0 == len(keyId) {
		err = fmt.Errorf("请求头缺失%q签名参数", keyIdParameter)
	} else if 0 == len(sig) {
		err = fmt.Errorf("请求头缺失%q签名参数", signatureParameter)
	} else if 0 == len(headers) {
		headers = defaultHeaders
	}

	return
}
