package hash

import (
	"testing"
)

func getHash() *Hash {
	h := NewHash(HashConfig{})
	return h
}

func TestHash_md5(t *testing.T) {
	h := getHash()

	// 加密字节数组
	result, err := h.Md5.Encrypt([]byte("abc"))
	if err != nil {
		t.Error(err)
	}
	t.Log(result)

	// 加密字符串
	result1, err := h.Md5.EncryptString("abc")
	if err != nil {
		t.Error(err)
	}
	t.Log(result1)
}

func TestHash_hmac(t *testing.T) {
	h := getHash()

	// 加密字节数组
	result, err := h.Hmac.Encrypt([]byte("abc"))
	if err != nil {
		t.Error(err)
	}
	t.Log(result)

	// 加密字符串
	result1, err := h.Hmac.EncryptString("abc")
	if err != nil {
		t.Error(err)
	}
	t.Log(result1)
}

func TestHash_sha1(t *testing.T) {
	h := getHash()

	// 加密字节数组
	result, err := h.Sha1.Encrypt([]byte("abc"))
	if err != nil {
		t.Error(err)
	}
	t.Log(result)

	// 加密字符串
	result1, err := h.Sha1.EncryptString("abc")
	if err != nil {
		t.Error(err)
	}
	t.Log(result1)
}

func TestHash_sha256(t *testing.T) {
	h := getHash()

	// 加密字节数组
	result, err := h.Sha256.Encrypt([]byte("abc"))
	if err != nil {
		t.Error(err)
	}
	t.Log(result)

	// 加密字符串
	result1, err := h.Sha256.EncryptString("abc")
	if err != nil {
		t.Error(err)
	}
	t.Log(result1)
}

func TestHash_sha512(t *testing.T) {
	h := getHash()

	// 加密字节数组
	result, err := h.Sha512.Encrypt([]byte("abc"))
	if err != nil {
		t.Error(err)
	}
	t.Log(result)

	// 加密字符串
	result1, err := h.Sha512.EncryptString("abc")
	if err != nil {
		t.Error(err)
	}
	t.Log(result1)
}
