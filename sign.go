package httpsig

import (
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
	prefixSeparator               = " "
	parameterKVSeparator          = "="
	parameterValueDelimiter       = "\""
	parameterSeparator            = ","
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

func setSignatureHeader(
	header http.Header, targetHeader string,
	prefix string, keyId string, alg string, enc string, created int64, expires int64, headers ...string,
) {
	if 0 == len(headers) {
		headers = defaultHeaders
	}

	var sb strings.Builder
	sb.WriteString(prefix)
	if 0 < len(prefix) {
		sb.WriteString(prefixSeparator)
	}
	sb.WriteString(keyIdParameter)
	sb.WriteString(parameterKVSeparator)
	sb.WriteString(parameterValueDelimiter)
	sb.WriteString(keyId)
	sb.WriteString(parameterValueDelimiter)
	sb.WriteString(parameterSeparator)

	sb.WriteString(algorithmParameter)
	sb.WriteString(parameterKVSeparator)
	sb.WriteString(parameterValueDelimiter)
	// 最新的协议要求，隐藏真实的算法
	alg = "hs2019"
	sb.WriteString(alg)
	sb.WriteString(parameterValueDelimiter)
	sb.WriteString(parameterSeparator)

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

	if hasCreated {
		sb.WriteString(createdKey)
		sb.WriteString(parameterKVSeparator)
		sb.WriteString(strconv.FormatInt(created, 10))
		sb.WriteString(parameterSeparator)
	}

	if hasExpires {
		sb.WriteString(expiresKey)
		sb.WriteString(parameterKVSeparator)
		sb.WriteString(strconv.FormatInt(expires, 10))
		sb.WriteString(parameterSeparator)
	}

	sb.WriteString(headersParameter)
	sb.WriteString(parameterKVSeparator)
	sb.WriteString(parameterValueDelimiter)
	for i, h := range headers {
		sb.WriteString(strings.ToLower(h))
		if i != len(headers)-1 {
			sb.WriteString(headerParameterValueDelimiter)
		}
	}
	sb.WriteString(parameterValueDelimiter)
	sb.WriteString(parameterSeparator)

	sb.WriteString(signatureParameter)
	sb.WriteString(parameterKVSeparator)
	sb.WriteString(parameterValueDelimiter)
	sb.WriteString(enc)
	sb.WriteString(parameterValueDelimiter)

	header.Add(targetHeader, sb.String())
}

func requestTargetNotPermitted(sb *strings.Builder) error {
	return fmt.Errorf("不能签名Http外的请求：%q", RequestTarget)
}

func addRequestTarget(r *http.Request) func(sb *strings.Builder) (err error) {
	return func(sb *strings.Builder) (err error) {
		sb.WriteString(RequestTarget)
		sb.WriteString(headerFieldDelimiter)
		sb.WriteString(strings.ToLower(r.Method))
		sb.WriteString(requestTargetSeparator)
		sb.WriteString(r.URL.Path)

		if "" != r.URL.RawQuery {
			sb.WriteString("?")
			sb.WriteString(r.URL.RawQuery)
		}

		return
	}
}

func signatureString(
	header http.Header,
	requestTargetFn func(sb *strings.Builder) error,
	created int64, expires int64,
	includes ...string,
) (signature string, err error) {
	if 0 == len(includes) {
		includes = defaultHeaders
	}

	var sb strings.Builder
	for index, include := range includes {
		include = strings.ToLower(include)
		if include == RequestTarget {
			if err = requestTargetFn(&sb); nil != err {
				return
			}
		} else if include == "("+expiresKey+")" {
			if 0 == expires {
				err = fmt.Errorf("未设置过期时间")

				return
			}
			sb.WriteString(include)
			sb.WriteString(headerFieldDelimiter)
			sb.WriteString(strconv.FormatInt(expires, 10))
		} else if include == "("+createdKey+")" {
			if 0 == created {
				err = fmt.Errorf("未设置创建时间")

				return
			}
			sb.WriteString(include)
			sb.WriteString(headerFieldDelimiter)
			sb.WriteString(strconv.FormatInt(created, 10))
		} else {
			headerValues, ok := header[textproto.CanonicalMIMEHeaderKey(include)]
			if !ok {
				err = fmt.Errorf("缺失请求头：%q", include)
			}
			sb.WriteString(include)
			sb.WriteString(headerFieldDelimiter)
			for i, headerValue := range headerValues {
				sb.WriteString(strings.TrimSpace(headerValue))
				if i < len(headerValues)-1 {
					sb.WriteString(headerValueDelimiter)
				}
			}
		}
		if index < len(includes)-1 {
			sb.WriteString(headersDelimiter)
		}
	}
	signature = sb.String()

	return
}
