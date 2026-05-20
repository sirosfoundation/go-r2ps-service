package service

import "encoding/base64"

func decodeBase64(s string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(s)
}

func encodeBase64(b []byte) string {
	return base64.URLEncoding.EncodeToString(b)
}
