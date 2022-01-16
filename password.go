package zdpgo_password

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"strings"

	"github.com/zhangdapeng520/zdpgo_password/plugins/pbkdf2"
)

const (
	defaultSaltLen    = 256
	defaultIterations = 10000
	defaultKeyLen     = 512
)

var (
	// 默认的hash算法
	defaultHashFunction = sha512.New

	// 默认选项
	defaultOptions = &Options{28, 100, 39, sha512.New}
)

type Options struct {
	SaltLen      int              // 盐的长度
	Iterations   int              // 迭代次数
	KeyLen       int              // 键的长度
	HashFunction func() hash.Hash // hash加密函数
}

// 生成盐
func generateSalt(length int) []byte {
	const alphanum = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	salt := make([]byte, length)
	rand.Read(salt)
	for key, val := range salt {
		salt[key] = alphanum[val%byte(len(alphanum))]
	}
	return salt
}

// Encode 对密码按照指定配置进行加密。如果参数2是nil，则使用默认的配置。返回加密后的字符串。
// @param rawPwd 要加密的密码
// @param options 加密配置
func Encode(rawPwd string, options *Options) (string, string) {
	// 使用默认的配置
	if options == nil {
		salt := generateSalt(defaultSaltLen)
		encodedPwd := pbkdf2.Key([]byte(rawPwd), salt, defaultIterations, defaultKeyLen, defaultHashFunction)
		return string(salt), hex.EncodeToString(encodedPwd)
	}

	// 使用自定义配置
	salt := generateSalt(options.SaltLen)                                                                    // 生成盐
	encodedPwd := pbkdf2.Key([]byte(rawPwd), salt, options.Iterations, options.KeyLen, options.HashFunction) // 加密
	return string(salt), hex.EncodeToString(encodedPwd)                                                      // 返回盐和加密后的字符串
}

// MakePassword 默认的密码加密方式，返回加密的密码
// @param rawPwd 要加密的密码
func MakePassword(rawPwd string) string {
	// 生成盐值和密码
	salt, encodedPwd := Encode(rawPwd, defaultOptions)

	// 组合密码
	newPassword := fmt.Sprintf("$pbkdf2-sha512$%s$%s", salt, encodedPwd)

	// 返回密码
	return newPassword
}

// Verify 校验密码
// @param rawPwd 原始密码
// @param salt 盐值
// @param encodedPwd 加密后的密码
// @param options 加密配置
// @return bool 校验密码是否正确
func Verify(rawPwd string, salt string, encodedPwd string, options *Options) bool {
	if options == nil {
		return encodedPwd == hex.EncodeToString(pbkdf2.Key([]byte(rawPwd), []byte(salt), defaultIterations, defaultKeyLen, defaultHashFunction))
	}
	return encodedPwd == hex.EncodeToString(pbkdf2.Key([]byte(rawPwd), []byte(salt), options.Iterations, options.KeyLen, options.HashFunction))
}

// CheckPassword 默认的密码校验方式
// @param rawPwd 原始密码
// @param encodedPwd 加密后的密码
func CheckPassword(rawPwd, encodedPwd string) bool {
	// 拆分密码
	passwordInfo := strings.Split(encodedPwd, "$")

	// 校验密码
	check := Verify(rawPwd, passwordInfo[2], passwordInfo[3], defaultOptions)

	// 返回校验结果
	return check
}
