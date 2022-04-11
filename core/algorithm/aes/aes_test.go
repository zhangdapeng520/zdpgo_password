package aes

import (
	"encoding/base64"
	"fmt"
	"testing"
)

func getAes() *Aes {
	return NewAes(AesConfig{})
}
func TestAes_ecb(t *testing.T) {
	a := getAes()
	data := "123 abc 张大鹏"

	// 加密
	encryptString, err := a.Ecb.EncryptString(data)
	if err != nil {
		t.Log(err)
	}
	t.Log(encryptString)

	// 解密
	decryptString, err := a.Ecb.DecryptString(encryptString)
	if err != nil {
		t.Error(err)
	}
	t.Log(decryptString)
}

func TestAes_cbc(t *testing.T) {
	a := getAes()
	data := "123 abc 张大鹏"

	// 加密
	encryptString, err := a.Cbc.EncryptString(data)
	if err != nil {
		t.Log(err)
	}
	t.Log(encryptString)

	// 解密
	decryptString, err := a.Cbc.DecryptString(encryptString)
	if err != nil {
		t.Error(err)
	}
	t.Log(decryptString)
}

func TestAes_ctr(t *testing.T) {
	a := getAes()
	data := "123 abc 张大鹏"
	t.Log(data)

	// 加密
	encryptString, err := a.Ctr.EncryptString(data)
	if err != nil {
		t.Log(err)
	}
	t.Log(encryptString)

	// 解密
	decryptString, err := a.Ctr.DecryptString(encryptString)
	if err != nil {
		t.Error(err)
	}
	t.Log(decryptString)
}

func TestAes_cfb(t *testing.T) {
	a := getAes()
	data := "123 abc 张大鹏"
	t.Log(data)

	// 加密
	encryptString, err := a.Cfb.EncryptString(data)
	if err != nil {
		t.Log(err)
	}
	t.Log(encryptString)

	// 解密
	decryptString, err := a.Cfb.DecryptString(encryptString)
	if err != nil {
		t.Error(err)
	}
	t.Log(decryptString)
}

func TestAes_ofb(t *testing.T) {
	a := getAes()
	data := "123 abc 张大鹏"
	t.Log(data)

	// 加密
	encryptString, err := a.Ofb.EncryptString(data)
	if err != nil {
		t.Log(err)
	}
	t.Log(encryptString)

	// 解密
	decryptString, err := a.Ofb.DecryptString(encryptString)
	if err != nil {
		t.Error(err)
	}
	t.Log(decryptString)
}

func TestAes_gcm(t *testing.T) {
	a := getAes()
	data := "123 abc 张大鹏"
	t.Log(data)

	// 加密
	encryptString, err := a.Gcm.EncryptString(data)
	if err != nil {
		t.Log(err)
	}
	t.Log(encryptString)

	// 解密
	decryptString, err := a.Gcm.DecryptString(encryptString)
	if err != nil {
		t.Error(err)
	}
	t.Log(decryptString)
}

func TestAes_self(t *testing.T) {
	a := getAes()
	data := "123 abc 张大鹏"
	t.Log(data)

	// 加密
	encryptString, err := a.EncryptString(data)
	if err != nil {
		t.Log(err)
	}
	t.Log(encryptString)

	// 解密
	decryptString, err := a.DecryptString(encryptString)
	if err != nil {
		t.Error(err)
	}
	t.Log(decryptString)
}

func TestAes_python(t *testing.T) {
	a := getAes()

	// 从Python复制过来的
	edata := "nZEhJnB7h6ow7pkA1WGHS6Qf0npQtuTbr6o="
	nonce := "3KICnt6GJVxANgC2ikhTNA=="
	tag := "gZUkLzz88GTDzNvA1vfzqA=="

	// 使用 -- 拼接 并使用base64编码
	data := fmt.Sprintf("%s--%s--%s", edata, nonce, tag)
	b64Data := base64.StdEncoding.EncodeToString([]byte(data))

	// 解密
	decryptString, err := a.DecryptString(b64Data)
	if err != nil {
		t.Error(err)
	}
	t.Log(decryptString)
}
