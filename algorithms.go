package jwt

import (
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"hash"
	"strings"
	"time"

	"github.com/pkg/errors"
)

//Algorithms is used to sign and validate a token
// 用于签发和验证 token
type Algorithm struct {
	signingHash hash.Hash
	algorithm   string
}

//NewHeader returns a header object
func (a *Algorithm) NewHeader() *Header {
	return &Header{
		Typ: "JWT",
		Alg: a.algorithm,
	}
}

// 对数据计算校验和
func (a *Algorithm) sum(data []byte) []byte {
	return a.signingHash.Sum(data)
}

func (a *Algorithm) reset() {
	a.signingHash.Reset()
}

func (a *Algorithm) write(data []byte) (int, error) {
	return a.signingHash.Write(data)
}

// Sign signs the token with the given hash, and key
// 对token进行签名（哈希）,要用用于消息验证的哈希算法 HMAC
func (a *Algorithm) Sign(unsignedToken string) ([]byte, error) {
	_, err := a.write([]byte(unsignedToken))
	if err != nil {
		return nil, errors.Wrap(err, "Unable to write to HMAC-SHA256")
	}
	encodedToken := a.sum(nil)
	a.reset()

	return encodedToken, nil
}

// encode returns an encoded JWT token from a header, payload and secret
// 对claims用哈希算法编码，并返回
func (a *Algorithm) Encode(payload *Claims) (string, error) {
	header := a.NewHeader()
	//1、对header序列化之后编码
	jsonTokenHeader, err := json.Marshal(header) // 序列化数据，type 和 algotithm（嵌套了多层的json）
	if err != nil {
		return "", errors.Wrap(err, "unable to marshal header")
	}
	b64TokenHeader := base64.RawURLEncoding.EncodeToString(jsonTokenHeader) // 将序列化之后的数据base64编码

	//2、对claimsMap序列化之后编码
	jsonTokenPayload, err := json.Marshal(payload.claimsMap) // 对claimMap中的数据序列化
	if err != nil {
		return "", errors.Wrap(err, "unable to marshal payload")
	}
	b64TokenPayload := base64.RawURLEncoding.EncodeToString(jsonTokenPayload)
	//签名 = 头信息 + "." + payload
	unsignedSignature := b64TokenHeader + "." + b64TokenPayload

	//3、对签名序列化之后编码
	signature, err := a.Sign(unsignedSignature)
	if err != nil {
		return "", errors.Wrap(err, "unable to sign token")
	}
	b64Signature := base64.RawURLEncoding.EncodeToString([]byte(signature))
	//4、得到token并返回
	token := b64TokenHeader + "." + b64TokenPayload + "." + b64Signature
	return token, nil
}

// Decode returns a map representing the token's claims. DOESN'T valiadate the claims though
// 解码数据，还原Claims
func (a *Algorithm) Decode(encoded string) (*Claims, error) {
	encryptedComponents := strings.Split(encoded, ".")
	if len(encryptedComponents) != 3 {
		return nil, errors.New("malformed token")
	}
	b64Payload := encryptedComponents[1]

	var claims map[string]interface{}

	//base64解码claims
	payload, err := base64.RawURLEncoding.DecodeString(b64Payload)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to decode base64 payload")
	}
	// 反序列化
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, errors.Wrap(err, "unable to Unmarshal payload json")
	}
	return &Claims{
		claimsMap: claims,
	}, nil
}

//Validate 验证，其实就是解码claims数据，然后比对
func (a *Algorithm) Validate(encoded string) error {
	_, err := a.DecodeAndValidate(encoded)
	return err

}

// DecodeAndValidate verifies a token validity. It returns  nil if it is valid, and an error if invalid
// 验证 token:验证token的签名（其实就是把header和payload签一下，然后和token里的最后一段对比是否一直），是否过期，是否在时间之前
func (a *Algorithm) DecodeAndValidate(encoded string) (claims *Claims, err error) {
	claims, err = a.Decode(encoded)
	if err != nil {
		return
	}
	if err = a.validateSignature(encoded); err != nil {
		err = errors.Wrap(err, "failed to validate signature")
		return
	}

	if err = a.validateExp(claims); err != nil {
		err = errors.Wrap(err, "failed to validate exp")
		return
	}

	if err = a.validateNbf(claims); err != nil {
		err = errors.Wrap(err, "failed to validate nbf")
	}
	return
}

// 验证签名
func (a *Algorithm) validateSignature(encoded string) error {
	encryptedComponents := strings.Split(encoded, ".")

	b64Header := encryptedComponents[0]
	b64Payload := encryptedComponents[1]
	// 签名信息
	b64Signature := encryptedComponents[2]

	unsignedAttempt := b64Header + "." + b64Payload
	signedAttempt, err := a.Sign(unsignedAttempt)
	if err != nil {
		return errors.Wrap(err, "unable to sign token for validation")
	}

	// 把haeader和 payload（claims）拿出来签名，然后和原来的签名对比，是否一样
	b64SignedAttempt := base64.RawURLEncoding.EncodeToString([]byte(signedAttempt))

	if !hmac.Equal([]byte(b64Signature), []byte(b64SignedAttempt)) {
		return errors.New("invalid signature")
	}

	return nil
}

// 验证是否过期，其实就是把payload(claims里的时间那段拿出来，对比一下当前时间)
func (a *Algorithm) validateExp(claims *Claims) error {
	if claims.HasClaim("exp") {
		exp, err := claims.GetTime("exp")
		if err != nil {
			return err
		}

		if exp.Before(time.Now()) {
			return errors.New("token has expired")
		}
	}

	return nil
}

// 验证是否在指定日期之前，其实就是把payload（claims里时间那段拿出来，对比一下当前时间）
func (a *Algorithm) validateNbf(claims *Claims) error {
	if claims.HasClaim("nbf") {
		nbf, err := claims.GetTime("nbf")
		if err != nil {
			return err
		}

		if nbf.After(time.Now()) {
			return errors.New("token isn't valid yet")
		}
	}

	return nil
}

//HmacSha256 returns the SingingMethod for HMAC with SHA256
//入参是Hash算法的key
func HmacSha256(key string) Algorithm {
	return Algorithm{
		algorithm:   "HS256",
		signingHash: hmac.New(sha256.New, []byte(key)),
	}
}

//HmacSha512 returns the SigningMethod for HMAC with SHA512
func HmacSha512(key string) Algorithm {
	return Algorithm{
		algorithm:   "HS512",
		signingHash: hmac.New(sha512.New, []byte(key)),
	}
}

//HmacSha384 returns the SigningMethod for HMAC with SHA384
func HmacSha384(key string) Algorithm {
	return Algorithm{
		algorithm:   "HS384",
		signingHash: hmac.New(crypto.SHA384.New, []byte(key)),
	}
}
