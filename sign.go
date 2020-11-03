package httpsig

import (
	"bytes"
	"fmt"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
)

const (
	keyIdParameter                = "keyId"
	algorithmParameter            = "algorithm"
	headersParameter              = "headers"
	signatureParameter            = "signature"
	prefixSeparater               = " "
	parameterKVSeparater          = "="
	parameterValueDelimiter       = "\""
	parameterSeparater            = ","
	headerParameterValueDelimiter = " "

	RequestTarget = "(request-target)"
	createdKey    = "created"
	expiresKey    = "expires"
	dateHeader    = "date"

	headerFieldDelimiter   = ": "
	headersDelimiter       = "\n"
	headerValueDelimiter   = ", "
	requestTargetSeparator = " "
)

var defaultHeaders = []string{dateHeader}

var _ Signer = &signerSymmetric{}

var _ Signer = &signerAsymmetric{}

var _ SSHSigner = &sshSignerAsymmetric{}

func setSignatureHeader(h http.Header, targetHeader, prefix, pubKeyId, algo, enc string, headers []string, created int64, expires int64) {
	if len(headers) == 0 {
		headers = defaultHeaders
	}
	var b bytes.Buffer
	// KeyId
	b.WriteString(prefix)
	if len(prefix) > 0 {
		b.WriteString(prefixSeparater)
	}
	b.WriteString(keyIdParameter)
	b.WriteString(parameterKVSeparater)
	b.WriteString(parameterValueDelimiter)
	b.WriteString(pubKeyId)
	b.WriteString(parameterValueDelimiter)
	b.WriteString(parameterSeparater)
	// Algorithm
	b.WriteString(algorithmParameter)
	b.WriteString(parameterKVSeparater)
	b.WriteString(parameterValueDelimiter)
	b.WriteString("hs2019") // real algorithm is hidden, see newest version of spec draft
	b.WriteString(parameterValueDelimiter)
	b.WriteString(parameterSeparater)

	hasCreated := false
	hasExpires := false
	for _, h := range headers {
		val := strings.ToLower(h)
		if val == "("+createdKey+")" {
			hasCreated = true
		} else if val == "("+expiresKey+")" {
			hasExpires = true
		}
	}

	// Created
	if hasCreated == true {
		b.WriteString(createdKey)
		b.WriteString(parameterKVSeparater)
		b.WriteString(strconv.FormatInt(created, 10))
		b.WriteString(parameterSeparater)
	}

	// Expires
	if hasExpires == true {
		b.WriteString(expiresKey)
		b.WriteString(parameterKVSeparater)
		b.WriteString(strconv.FormatInt(expires, 10))
		b.WriteString(parameterSeparater)
	}

	// Headers
	b.WriteString(headersParameter)
	b.WriteString(parameterKVSeparater)
	b.WriteString(parameterValueDelimiter)
	for i, h := range headers {
		b.WriteString(strings.ToLower(h))
		if i != len(headers)-1 {
			b.WriteString(headerParameterValueDelimiter)
		}
	}
	b.WriteString(parameterValueDelimiter)
	b.WriteString(parameterSeparater)
	// Signature
	b.WriteString(signatureParameter)
	b.WriteString(parameterKVSeparater)
	b.WriteString(parameterValueDelimiter)
	b.WriteString(enc)
	b.WriteString(parameterValueDelimiter)
	h.Add(targetHeader, b.String())
}

func requestTargetNotPermitted(b *bytes.Buffer) error {
	return fmt.Errorf("cannot sign with %q on anything other than an http request", RequestTarget)
}

func addRequestTarget(r *http.Request) func(b *bytes.Buffer) error {
	return func(b *bytes.Buffer) error {
		b.WriteString(RequestTarget)
		b.WriteString(headerFieldDelimiter)
		b.WriteString(strings.ToLower(r.Method))
		b.WriteString(requestTargetSeparator)
		b.WriteString(r.URL.Path)

		if r.URL.RawQuery != "" {
			b.WriteString("?")
			b.WriteString(r.URL.RawQuery)
		}

		return nil
	}
}

func signatureString(values http.Header, include []string, requestTargetFn func(b *bytes.Buffer) error, created int64, expires int64) (string, error) {
	if len(include) == 0 {
		include = defaultHeaders
	}
	var b bytes.Buffer
	for n, i := range include {
		i := strings.ToLower(i)
		if i == RequestTarget {
			err := requestTargetFn(&b)
			if err != nil {
				return "", err
			}
		} else if i == "("+expiresKey+")" {
			if expires == 0 {
				return "", fmt.Errorf("missing expires value")
			}
			b.WriteString(i)
			b.WriteString(headerFieldDelimiter)
			b.WriteString(strconv.FormatInt(expires, 10))
		} else if i == "("+createdKey+")" {
			if created == 0 {
				return "", fmt.Errorf("missing created value")
			}
			b.WriteString(i)
			b.WriteString(headerFieldDelimiter)
			b.WriteString(strconv.FormatInt(created, 10))
		} else {
			hv, ok := values[textproto.CanonicalMIMEHeaderKey(i)]
			if !ok {
				return "", fmt.Errorf("missing header %q", i)
			}
			b.WriteString(i)
			b.WriteString(headerFieldDelimiter)
			for i, v := range hv {
				b.WriteString(strings.TrimSpace(v))
				if i < len(hv)-1 {
					b.WriteString(headerValueDelimiter)
				}
			}
		}
		if n < len(include)-1 {
			b.WriteString(headersDelimiter)
		}
	}
	return b.String(), nil
}
