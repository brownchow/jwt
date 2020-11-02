package jwt

// Header 包含了重要的诸如加密、解密信息
type Header struct {
	Typ string `json:"typ"` // Token type
	Alg string `json:"alg"` // Message Authentication Code Algorithm - The issuer can freely set an algorithm to verify the signature on the token. However, some asymmetrical algorithms pose security concerns
	Cty string `json:"cty"` // Content Type This claim should always be JWT
}
