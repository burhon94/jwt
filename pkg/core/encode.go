package core

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

func Encode(payload interface{}, secret Secret) (token string, err error) {
	headerJSON, err := json.Marshal(defaultHeader)
	if err != nil {
		return "", errors.New("can't marshal header")
	}
	headerEncoded := base64.RawURLEncoding.EncodeToString(headerJSON)

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", errors.New("can't marshall payload")
	}
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signatureEncoded := calculateSignatureEncoded(headerEncoded, payloadEncoded, secret)

	return fmt.Sprintf("%s.%s.%s", headerEncoded, payloadEncoded, signatureEncoded), nil
}
