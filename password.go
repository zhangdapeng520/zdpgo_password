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

// Options is a struct for custom values of salt length, number of iterations, the encoded key's length,
// and the hash function being used. If set to `nil`, default options are used:
// &Options{ 256, 10000, 512, "sha512" }
type Options struct {
	SaltLen      int // 盐的长度
	Iterations   int
	KeyLen       int // 键的长度
	HashFunction func() hash.Hash
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

// Encode takes two arguments, a raw password, and a pointer to an Options struct.
// In order to use default options, pass `nil` as the second argument.
// It returns the generated salt and encoded key for the user.
func Encode(rawPwd string, options *Options) (string, string) {
	if options == nil {
		salt := generateSalt(defaultSaltLen)
		encodedPwd := pbkdf2.Key([]byte(rawPwd), salt, defaultIterations, defaultKeyLen, defaultHashFunction)
		return string(salt), hex.EncodeToString(encodedPwd)
	}
	salt := generateSalt(options.SaltLen)
	encodedPwd := pbkdf2.Key([]byte(rawPwd), salt, options.Iterations, options.KeyLen, options.HashFunction)
	return string(salt), hex.EncodeToString(encodedPwd)
}

// 默认的密码加密方式，返回加密的密码
func MakePassword(rawPwd string) string {
	// 生成盐值和密码
	salt, encodedPwd := Encode(rawPwd, defaultOptions)

	// 组合密码
	newPassword := fmt.Sprintf("$pbkdf2-sha512$%s$%s", salt, encodedPwd)

	// 返回密码
	return newPassword
}

// Verify takes four arguments, the raw password, its generated salt, the encoded password,
// and a pointer to the Options struct, and returns a boolean value determining whether the password is the correct one or not.
// Passing `nil` as the last argument resorts to default options.
func Verify(rawPwd string, salt string, encodedPwd string, options *Options) bool {
	if options == nil {
		return encodedPwd == hex.EncodeToString(pbkdf2.Key([]byte(rawPwd), []byte(salt), defaultIterations, defaultKeyLen, defaultHashFunction))
	}
	return encodedPwd == hex.EncodeToString(pbkdf2.Key([]byte(rawPwd), []byte(salt), options.Iterations, options.KeyLen, options.HashFunction))
}

// 默认的密码校验方式
func CheckPassword(rawPwd, encodedPwd string) bool {
	// 拆分密码
	passwordInfo := strings.Split(encodedPwd, "$")

	// 校验密码
	check := Verify(rawPwd, passwordInfo[2], passwordInfo[3], defaultOptions)

	// 返回校验结果
	return check
}
