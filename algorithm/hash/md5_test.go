package hash

import "testing"

func getMd5() *Md5 {
	return NewMd5("abc")
}

func TestMd5_Encrypt(t *testing.T) {
	m := getMd5()
	result, err := m.Encrypt([]byte("abc"))
	t.Log(string(result))
	if err != nil {
		t.Error(err)
	}
}

func TestMd5_EncryptString(t *testing.T) {
	m := getMd5()
	result, err := m.EncryptString("abc")
	t.Log(result)
	if err != nil {
		t.Error(err)
	}
}
