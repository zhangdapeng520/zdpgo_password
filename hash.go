package zdpgo_password

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
)

// GetMd5 获取一个文本的md5值
func GetMd5(text string) string {
	data := []byte(text)
	has := md5.Sum(data)
	md5str1 := fmt.Sprintf("%x", has) //将[]byte转成16进制
	return md5str1
}

// GetMd5WithKey 使用指定key获取一个文本的md5值
func GetMd5WithKey(key, data string) string {
	// 创建md5加密对象
	h := md5.New()

	// 加密数据
	h.Write([]byte(data))

	// 返回加密后的数据
	return hex.EncodeToString(h.Sum([]byte(key)))
}

// CheckMd5 检查加密字符串是否正确
// @param md5Str md5加密后的16进制字符串
// @param originStr 要检查的加密前的数据
// 返回一个布尔值
func CheckMd5(originStr, md5Str string) bool {
	t := GetMd5(originStr)
	return t == md5Str
}

// CheckMd5WithKey 使用指定key检查字符串是否和md5加密后的字符串相同
// @param key 指定的加密key
// @param originStr 加密前字符串
// @param md5Str 加密后字符串
func CheckMd5WithKey(key, originStr, md5Str string) bool {
	t := GetMd5WithKey(key, originStr)
	return t == md5Str
}

func GetSha1(text string) string {
	data := []byte(text)
	has := sha1.Sum(data)
	md5str1 := fmt.Sprintf("%x", has) //将[]byte转成16进制
	return md5str1
}

func CheckSha1(originStr, md5Str string) bool {
	t := GetSha1(originStr)
	return t == md5Str
}

func GetSha1WithKey(key, data string) string {
	// 创建sha1对象
	s := sha1.New()

	// 对数据进行加密
	s.Write([]byte(data))

	// 返回加密数据
	return hex.EncodeToString(s.Sum([]byte(key)))
}

func CheckSha1WithKey(key, originStr, sha1Str string) bool {
	t := GetSha1WithKey(key, originStr)
	return t == sha1Str
}

func GetSha256WithKey(key, data string) string {
	// 创建sha1对象
	s := sha256.New()

	// 对数据进行加密
	s.Write([]byte(data))

	// 返回加密数据
	return hex.EncodeToString(s.Sum([]byte(key)))
}

func CheckSha256WithKey(key, originStr, sha1Str string) bool {
	t := GetSha256WithKey(key, originStr)
	return t == sha1Str
}

func GetSha512WithKey(key, data string) string {
	// 创建sha1对象
	s := sha512.New()

	// 对数据进行加密
	s.Write([]byte(data))

	// 返回加密数据
	return hex.EncodeToString(s.Sum([]byte(key)))
}

func CheckSha512WithKey(key, originStr, sha1Str string) bool {
	t := GetSha512WithKey(key, originStr)
	return t == sha1Str
}
