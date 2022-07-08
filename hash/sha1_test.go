package hash

import (
	"fmt"
	"testing"
)

func getSha1() *Sha1 {
	return NewSha1("abc")
}

func TestSha1_Encrypt(t *testing.T) {
	s := getSha1()
	data := "abc"

	// 加密
	encrypt, err := s.Encrypt([]byte(data))
	fmt.Println(encrypt, err)

	// 解密
	encryptString, err := s.EncryptString(data)
	fmt.Println(encryptString, err)
}
