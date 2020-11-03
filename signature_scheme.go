package httpsig

// SignatureScheme 签名类型
type SignatureScheme string

const (
	// Signature 使用Signature头鉴权方式
	Signature SignatureScheme = "Signature"
	// Authorization 使用Authorization的鉴权方式
	Authorization SignatureScheme = "Authorization"

	signatureAuthScheme = "Signature"
)

func (ss SignatureScheme) authScheme() (scheme string) {
	switch ss {
	case Authorization:
		scheme = signatureAuthScheme
	default:
		scheme = ""
	}

	return
}
