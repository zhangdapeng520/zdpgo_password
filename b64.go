package zdpgo_password

import (
	"encoding/base64"
)

// Base64Encode 对数据使用base64标准编码
func Base64Encode(data []byte) string {
	sEnc := base64.StdEncoding.EncodeToString(data)
	return sEnc
}

// Base64Decode 对数据使用base64标准解码
func Base64Decode(data string) string {
	sDec, _ := base64.StdEncoding.DecodeString(data)
	return string(sDec)
}

// Base64URLEncode 对数据使用base64 URL编码
func Base64URLEncode(data []byte) string {
	sEnc := base64.URLEncoding.EncodeToString(data)
	return sEnc
}

// Base64URLDecode 对数据使用base64 URL解码
func Base64URLDecode(data string) string {
	sDec, _ := base64.URLEncoding.DecodeString(data)
	return string(sDec)
}
