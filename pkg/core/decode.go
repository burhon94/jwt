package core

import (
	"encoding/base64"
	"encoding/json"
	"errors"
)

func Decode(token string, payload interface{}) (err error) {
	parts, err := tokenSplitter(token)
	if err != nil {
		return err
	}

	headerEncoded := parts[0]
	headerJSON, err := base64.RawURLEncoding.DecodeString(headerEncoded)
	if err != nil {
		return errors.New("can't decode header")
	}
	err = json.Unmarshal(headerJSON, payload)
	if err != nil {
		return errors.New("can't unmarshall header")
	}


	payloadEncoded := parts[1]
	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadEncoded)
	if err != nil {
		return errors.New("can't decode payload")
	}
	err = json.Unmarshal(payloadJSON, payload)
	if err != nil {
		return errors.New("can't unmarshall payload")
	}

	return nil
}
