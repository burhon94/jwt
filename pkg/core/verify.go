package core

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"reflect"
	"time"
)

func Verify(token string, secret Secret) (ok bool, err error) {
	parts, err := tokenSplitter(token)
	if err != nil {
		err = errors.New("invalid token: token should contain header, payloadStruct and secret")
		return false, err
	}
	headerEncoded, payloadEncoded, signatureEncoded := parts[0], parts[1], parts[2]

	verificationEncoded := calculateSignatureEncoded(headerEncoded, payloadEncoded, secret)
	return signatureEncoded == verificationEncoded, nil
}

func IsNotExpired(payload interface{}, moment time.Time) (ok bool, err error) {
	reflectType := reflect.TypeOf(payload)
	reflectValue := reflect.ValueOf(payload)
	if reflectType.Kind() == reflect.Ptr {
		reflectType = reflectType.Elem()
		reflectValue = reflectValue.Elem()
	}

	if reflectType.Kind() != reflect.Struct {
		return false, errors.New("give me struct or pointer to it")
	}

	fieldCount := reflectType.NumField()
	for i := 0; i < fieldCount; i++ {
		field := reflectType.Field(i)
		// TODO: move this to const
		tag, ok := field.Tag.Lookup("json")
		if !ok {
			continue
		}
		// TODO: move this to const
		if tag == "exp" {
			value := reflectValue.Field(i)
			if value.Kind() != reflect.Int64 {
				return false, errors.New("exp should be int64")
			}
			exp := value.Interface().(int64)
			return exp > moment.Unix(), nil
		}
	}

	panic(errors.New("no field with json:exp tag"))
}

func calculateSignatureEncoded(headerEncoded string, payloadEncoded string, secret []byte) string {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(headerEncoded + "." + payloadEncoded))
	signature := h.Sum(nil)

	return base64.RawURLEncoding.EncodeToString(signature)
}
