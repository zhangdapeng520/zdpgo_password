package hash

import "testing"

func getHmac() *Hmac {
	m := NewHmac("abc", "sha1")
	return m
}

func TestHmac_Encrypt(t *testing.T) {
	m := getHmac()
	result, err := m.Encrypt([]byte("abc"))
	if err != nil {
		t.Error(err)
	}
	t.Log(result)
}

func TestHmac_EncryptString(t *testing.T) {
	m := getHmac()
	result, err := m.EncryptString("abc")
	if err != nil {
		t.Error(err)
	}
	t.Log(result)
}
