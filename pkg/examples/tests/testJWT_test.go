package tests

import (
	pkg "github.com/burhon94/jwt/pkg/core"
	"strings"
	"testing"
	"time"
)

type payload struct {
	Id  int   `json:"id"`
	Iat int64 `json:"iat"`
	Exp int64 `json:"exp"`
}

var	defaultPayload = payload{
	Id:  1,
	Iat: time.Now().Unix(),
	Exp: time.Now().Add(time.Hour * 10).Unix(),
}

var secretKey = "booToken"
var key = pkg.Secret([]byte(secretKey))

func TestEncodeDecode_OK(t *testing.T) {
	secretKey := "booToken"
	key := pkg.Secret(secretKey)
	token, err := pkg.Encode(defaultPayload, key)
	if err != nil {
		t.Fatalf("just be nil, while encode: %v", err)
	}

	if pkg.Decode(token, &defaultPayload) != nil {
		t.Fatalf("just be nil, while encode token: %v", err)
	}
}

func TestDecode_Err_BadTokenHeader(t *testing.T) {
	if pkg.Decode("BadToken.Foo.Boo", defaultPayload) == nil {
		t.Fatal("just be err, while decode bad token header")
	}
}

func TestDecode_Err_BadTokenPayload(t *testing.T) {
	if pkg.Decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.Foo.Boo", defaultPayload) == nil {
		t.Fatal("just be err, while decode bad token header")
	}
}

func TestEncodeDecode_Err_PartsToken(t *testing.T) {
	token, err := pkg.Encode(defaultPayload, key)
	if err != nil {
		t.Fatalf("just be nil, while encode: %v", err)
	}

	testTokens := strings.Split(token, ".")
	token = testTokens[0] + testTokens[2]

	if pkg.Decode(token, defaultPayload) == nil {
		t.Fatalf("just be err: %v", err)
	}
}

func TestDecode_Err_BadTokenHeaderNoStruct(t *testing.T) {

	token, err := pkg.Encode(defaultPayload, key)
	if err != nil {
		t.Fatalf("just be nil, while encode: %v", err)
	}

	if pkg.Decode(token, "payload") == nil {
		t.Fatal("just be err, while decode bad token header no struct")
	}
}

func TestDecode_Err_BadTokenPayloadNoStruct(t *testing.T) {
	token, err := pkg.Encode(defaultPayload, key)
	if err != nil {
		t.Fatalf("just be nil, while encode: %v", err)
	}

	if pkg.Decode(token, "payload") == nil {
		t.Fatal("just be err, while decode bad token header no struct")
	}
}

func TestVerify_OK(t *testing.T) {
	token, err := pkg.Encode(defaultPayload, key)
	if err != nil {
		t.Fatalf("just be nil, while encode: %v", err)
	}

	if pkg.Decode(token, &defaultPayload) != nil {
		t.Fatalf("just be nil, while encode token: %v", err)
	}

	ok, err := pkg.Verify(token, key)
	if err != nil {
		t.Fatalf("just bi nil: %v", err)
	}
	if !ok	{
		t.Fatalf("just be nil, while verify: %v", err)
	}
}

func TestVerify_Err_Verify(t *testing.T) {
	token, err := pkg.Encode(defaultPayload, key)
	if err != nil {
		t.Fatalf("just be nil, while encode: %v", err)
	}

	if pkg.Decode(token, defaultPayload) != nil {

	}

	key = pkg.Secret("secret")
	secretKey := key
	ok, err := pkg.Verify(token, secretKey)

	ok, err = pkg.Verify(token, key)
	if err != nil {
		t.Fatalf("just bi nil: %v", err)
	}
	if ok	{
		t.Fatalf("just be nil, while encode token: %v", err)
	}
}

func TestVerify_TokenExpired(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwiaWF0IjoxNTgzOTQ3OTU2LCJleHAiOjE1ODM5ODM5NTZ9.PalLcAtVCmYUC9mQZFvfD3mBSICRbLT4VO_jS6dkSWc"

	if pkg.Decode(token, &defaultPayload) != nil {
		t.Fatal("just be nil, while encode token")
	}

	ok, _ := pkg.Verify(token, key)
	if ok {
		t.Fatal("just be err, while token expired")
	}

}

func TestVerify_Err_Verify_PartsToken(t *testing.T) {

	token, err := pkg.Encode(defaultPayload, key)
	if err != nil {
		t.Fatalf("just be nil, while encode: %v", err)
	}

	if pkg.Decode(token, &defaultPayload) != nil {
		t.Fatalf("just be nil, while encode token: %v", err)
	}

	testTokens := strings.Split(token, ".")
	token = testTokens[0] + testTokens[2]

	_, err = pkg.Verify(token, key)
	if err == nil {
		t.Fatalf("just be nil, while verify: %v", err)
	}
}
