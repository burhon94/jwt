package core

import (
	"errors"
	"strings"
)

type Secret []byte

type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

var defaultHeader = Header{
	Alg: "HS256",
	Typ: "JWT",
}

func tokenSplitter(token string) (parts []string, err error) {
	parts = strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("bad token")
	}

	return parts, nil
}
