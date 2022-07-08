package zdpgo_password

import (
	"github.com/zhangdapeng520/zdpgo_password/aes"
	"github.com/zhangdapeng520/zdpgo_password/hash"
	"testing"
)

func getPassword() *Password {
	p := NewWithConfig(&Config{
		Aes:  aes.AesConfig{},
		Hash: hash.HashConfig{},
	})
	return p
}

// 测试hash加密方法
func TestPassword_hash(t *testing.T) {
	p := getPassword()

	data := "abc 123 张大鹏"

	var (
		err error
	)

	// md5加密
	_, err = p.Hash.Md5.EncryptString(data)
	if err != nil {
		t.Error(err)
	}

	// hmac加密
	_, err = p.Hash.Hmac.EncryptString(data)
	if err != nil {
		t.Error(err)
	}

	// sha1加密
	_, err = p.Hash.Sha1.EncryptString(data)
	if err != nil {
		t.Error(err)
	}

	// sha256加密
	_, err = p.Hash.Sha256.EncryptString(data)
	if err != nil {
		t.Error(err)
	}

	// sha512加密
	_, err = p.Hash.Sha512.EncryptString(data)
	if err != nil {
		t.Error(err)
	}
}

// 测试AES加密方法
func TestPassword_aes(t *testing.T) {
	p := getPassword()

	data := "abc 123 张大鹏"

	var (
		result string
		err    error
	)

	// 默认加密解密
	result, err = p.Aes.EncryptString(data)
	if err != nil {
		t.Error(err)
	}
	result, err = p.Aes.DecryptString(result)
	if err != nil {
		t.Error(err)
	}

	// GCM模式加密解密
	result, err = p.Aes.Gcm.EncryptString(data)
	if err != nil {
		t.Error(err)
	}
	result, err = p.Aes.Gcm.DecryptString(result)
	if err != nil {
		t.Error(err)
	}

	// OFB模式加密解密
	result, err = p.Aes.Ofb.EncryptString(data)
	if err != nil {
		t.Error(err)
	}
	result, err = p.Aes.Ofb.DecryptString(result)
	if err != nil {
		t.Error(err)
	}

	// ECB模式加密解密
	result, err = p.Aes.Ecb.EncryptString(data)
	if err != nil {
		t.Error(err)
	}
	result, err = p.Aes.Ecb.DecryptString(result)
	if err != nil {
		t.Error(err)
	}

	// CFB模式加密解密
	result, err = p.Aes.Cfb.EncryptString(data)
	if err != nil {
		t.Error(err)
	}
	result, err = p.Aes.Cfb.DecryptString(result)
	if err != nil {
		t.Error(err)
	}

	// CTR模式加密解密
	result, err = p.Aes.Ctr.EncryptString(data)
	if err != nil {
		t.Error(err)
	}
	result, err = p.Aes.Ctr.DecryptString(result)
	if err != nil {
		t.Error(err)
	}

	// CBC模式加密解密
	result, err = p.Aes.Cbc.EncryptString(data)
	if err != nil {
		t.Error(err)
	}
	result, err = p.Aes.Cbc.DecryptString(result)
	if err != nil {
		t.Error(err)
	}
}

// 测试基本使用
func TestUrl_basic(t *testing.T) {
	p := getPassword()
	urlPath := "https://www.google.com?kw=张大鹏"

	// 编码
	urlEncode := p.Url.Encode(urlPath)

	// 解码
	_, err := p.Url.Decode(urlEncode)
	if err != nil {
		t.Error(err)
	}
}

// 十六进制的基本使用
func TestHex_basic(t *testing.T) {
	data := "abc 123 张大鹏"

	// 编码
	h := getPassword()
	encode := h.Hex.Encode([]byte(data))

	// 解码
	_, err := h.Hex.Decode(encode)
	if err != nil {
		t.Error(err)
	}

	// 编码字符串
	encodeString := h.Hex.EncodeString(data)

	// 解码字符串
	_, err = h.Hex.DecodeString(encodeString)
	if err != nil {
		t.Error(err)
	}
}
