package jwt

import (
	"time"

	"github.com/pkg/errors"
)

// Claims contains the claims of a jwt
// Claims就是一个Map，存放各种键值对，提供存取功能
type Claims struct {
	claimsMap map[string]interface{}
}

// NewClaim returns a new map representing the claims with the default values. The schema is detailed below.
//		claim["iis"] Issuer - string - identifies principal that issued the JWT;
//		claim["sub"] Subject - string - identifies the subject of the JWT;
//		claim["aud"] Audience - string - The "aud" (audience) claim identifies the recipients that the JWT is intended for. Each principal intended to process the JWT MUST identify itself with a value in the audience claim. If the principal processing the claim does not identify itself with a value in the aud claim when this claim is present, then the JWT MUST be rejected.
//		claim["exp"] Expiration time - time - The "exp" (expiration time) claim identifies the expiration time on or after which the JWT MUST NOT be accepted for processing.
//		claim["nbf"] Not before - time - Similarly, the not-before time claim identifies the time on which the JWT will start to be accepted for processing.
//		claim["iat"] Issued at - time - The "iat" (issued at) claim identifies the time at which the JWT was issued.
//		claim["jti"] JWT ID - string - case sensitive unique identifier of the token even among different issuers.
func NewClaims() *Claims {
	claimsMap := make(map[string]interface{})

	claims := &Claims{
		claimsMap: claimsMap,
	}
	claims.SetTime("iat", time.Now())
	return claims
}

func (c *Claims) Set(key string, value interface{}) {
	c.claimsMap[key] = value
}

func (c *Claims) SetTime(key string, value time.Time) {
	c.Set(key, value.Unix())
}

func (c Claims) Get(key string) (interface{}, error) {
	result, ok := c.claimsMap[key]
	if !ok {
		return "", errors.Errorf("claim (%s) doesn't exist", key)
	}
	return result, nil
}

func (c *Claims) GetTime(key string) (time.Time, error) {
	raw, err := c.Get(key)
	if err != nil {
		return time.Unix(0, 0), errors.Wrapf(err, "claim (%s) doesn't exist", key)
	}
	// 类型转换
	timeFloat, ok := raw.(float64)
	if !ok {
		return time.Unix(0, 0), errors.Wrapf(err, "claim isn't a valid float")
	}
	return time.Unix(int64(timeFloat), 0), nil
}

func (c *Claims) HasClaim(key string) bool {
	_, ok := c.claimsMap[key]
	return ok
}
