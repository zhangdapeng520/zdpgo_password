package zdpgo_password

import (
	"github.com/zhangdapeng520/zdpgo_password/algorithm/aes"
	"github.com/zhangdapeng520/zdpgo_password/algorithm/hash"
	"github.com/zhangdapeng520/zdpgo_password/algorithm/rsa"
	"testing"
)

func getPassword() *Password {
	p := New(PasswordConfig{
		Debug:       true,
		LogFilePath: "",
		Aes:         aes.AesConfig{},
		Rsa:         rsa.RsaConfig{},
		Hash:        hash.HashConfig{},
	})
	return p
}

// 测试hash加密方法
func TestPassword_hash(t *testing.T) {
	p := getPassword()

	data := "abc 123 张大鹏"
	t.Log(data)

	var (
		result string
		err    error
	)

	// md5加密
	result, err = p.Hash.Md5.EncryptString(data)
	if err != nil {
		t.Error(err)
	}
	t.Log(result)

	// hmac加密
	result, err = p.Hash.Hmac.EncryptString(data)
	if err != nil {
		t.Error(err)
	}
	t.Log(result)

	// sha1加密
	result, err = p.Hash.Sha1.EncryptString(data)
	if err != nil {
		t.Error(err)
	}
	t.Log(result)

	// sha256加密
	result, err = p.Hash.Sha256.EncryptString(data)
	if err != nil {
		t.Error(err)
	}
	t.Log(result)

	// sha512加密
	result, err = p.Hash.Sha512.EncryptString(data)
	if err != nil {
		t.Error(err)
	}
	t.Log(result)
}

// 测试AES加密方法
func TestPassword_aes(t *testing.T) {
	p := getPassword()

	data := "abc 123 张大鹏"
	t.Log(data)

	var (
		result string
		err    error
	)

	// 默认加密解密
	result, err = p.Aes.EncryptString(data)
	if err != nil {
		t.Error(err)
	}
	t.Log(result)
	result, err = p.Aes.DecryptString(result)
	if err != nil {
		t.Error(err)
	}
	t.Log(result)

	// GCM模式加密解密
	result, err = p.Aes.Gcm.EncryptString(data)
	if err != nil {
		t.Error(err)
	}
	t.Log(result)
	result, err = p.Aes.Gcm.DecryptString(result)
	if err != nil {
		t.Error(err)
	}
	t.Log(result)

	// OFB模式加密解密
	result, err = p.Aes.Ofb.EncryptString(data)
	if err != nil {
		t.Error(err)
	}
	t.Log(result)
	result, err = p.Aes.Ofb.DecryptString(result)
	if err != nil {
		t.Error(err)
	}
	t.Log(result)

	// ECB模式加密解密
	result, err = p.Aes.Ecb.EncryptString(data)
	if err != nil {
		t.Error(err)
	}
	t.Log(result)
	result, err = p.Aes.Ecb.DecryptString(result)
	if err != nil {
		t.Error(err)
	}
	t.Log(result)

	// CFB模式加密解密
	result, err = p.Aes.Cfb.EncryptString(data)
	if err != nil {
		t.Error(err)
	}
	t.Log(result)
	result, err = p.Aes.Cfb.DecryptString(result)
	if err != nil {
		t.Error(err)
	}
	t.Log(result)

	// CTR模式加密解密
	result, err = p.Aes.Ctr.EncryptString(data)
	if err != nil {
		t.Error(err)
	}
	t.Log(result)
	result, err = p.Aes.Ctr.DecryptString(result)
	if err != nil {
		t.Error(err)
	}
	t.Log(result)

	// CBC模式加密解密
	result, err = p.Aes.Cbc.EncryptString(data)
	if err != nil {
		t.Error(err)
	}
	t.Log(result)
	result, err = p.Aes.Cbc.DecryptString(result)
	if err != nil {
		t.Error(err)
	}
	t.Log(result)
}

// 测试RSA加密方法
func TestPassword_rsa(t *testing.T) {
	p := getPassword()

	data := "abc 123 张大鹏"
	t.Log(data)

	var (
		result string
		err    error
	)

	// 默认加密解密
	result, err = p.Rsa.EncryptString(data)
	if err != nil {
		t.Error(err)
	}
	t.Log(result)
	result, err = p.Rsa.DecryptString(result)
	if err != nil {
		t.Error(err)
	}
	t.Log(result)

	// SHA1模式加密解密
	result, err = p.Rsa.Sha1.EncryptString(data)
	if err != nil {
		t.Error(err)
	}
	t.Log(result)
	result, err = p.Rsa.Sha1.DecryptString(result)
	if err != nil {
		t.Error(err)
	}
	t.Log(result)
}

// 测试ECC加密解密
func TestPassword_ecc(t *testing.T) {
	p := getPassword()

	data := "abc 123 张大鹏"
	t.Log(data)

	var (
		result string
		err    error
	)

	// 默认加密解密
	result, err = p.Ecc.EncryptString(data)
	if err != nil {
		t.Error(err)
	}
	t.Log(result)
	result, err = p.Ecc.DecryptString(result)
	if err != nil {
		t.Error(err)
	}
	t.Log(result)
}
