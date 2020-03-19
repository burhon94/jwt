package main

import (
	"fmt"
	pkg "github.com/burhon94/jwt/pkg/core"
	"log"
	"time"
)

type payloadStruct struct {
	Id  int   `json:"id"`
	Iat int64 `json:"iat"`
	Exp int64 `json:"exp"`
}

var payload = payloadStruct{
	Id:  1,
	Iat: time.Now().Unix(),
	Exp: time.Now().Add(time.Hour * 10).Unix(),
}

var secretKey = "booToken"
var key = pkg.Secret(secretKey)

func main() {
	token, err := pkg.Encode(payload, key)
	if err != nil {
		panic(fmt.Sprintf("i can't encode: %v", err))
	}
	log.Print(token)

	if pkg.Decode(token, &payload) != nil {
		panic(fmt.Sprintf("i can't decode: %v", err))
	}

	ok, err := pkg.Verify(token, key)
	if err != nil {
		panic(fmt.Sprintf("i can't verify tooken: %v", err))
	}

	if !ok {
		panic(fmt.Sprintf("token is not verify: %v", err))
	}

	timeNow := time.Now()

	isExpired, err := pkg.IsNotExpired(payload, timeNow)
	if err != nil {
		panic(fmt.Sprintf("i can't check expired"))
	}

	if !isExpired {
		panic(fmt.Sprintf("expired is"))
	}
}
