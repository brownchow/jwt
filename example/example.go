package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/brownchow/jwt"
)

func main() {
	// 服务端密钥
	secret := "ThisIsMySuperSecret"
	algorithm := jwt.HmacSha256(secret)

	claims := jwt.NewClaims()
	claims.Set("Role", "Admin")
	claims.SetTime("exp", time.Now().Add(time.Minute))

	// 对claim编码，得到token，发送给客户端
	token, err := algorithm.Encode(claims)
	if err != nil {
		panic(err)
	}
	// 查看token
	fmt.Printf("Token: %s\n", token)

	// 客户端把把jwt发给服务端，服务端验证
	if algorithm.Validate(token) != nil {
		panic(err)
	}

	// 服务端解码jwt
	loadedClaims, err := algorithm.Decode(token)
	if err != nil {
		panic(err)
	}

	role, err := loadedClaims.Get("Role")
	if err != nil {
		panic(err)
	}

	roleString, ok := role.(string)
	if !ok {
		panic(err)
	}

	if strings.Compare(roleString, "Admin") == 0 {
		//user is an admin
		fmt.Println("User is an admin")
	}
}
