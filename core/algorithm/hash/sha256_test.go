package hash

import (
	"fmt"
	"testing"
)

func getSha256() *Sha256 {
	return NewSha256("abc")
}

func TestSha256_Encrypt(t *testing.T) {
	s := getSha256()
	data := "abc"

	// 加密
	encrypt, err := s.Encrypt([]byte(data))
	fmt.Println(encrypt, err)

	// 解密
	encryptString, err := s.EncryptString(data)
	fmt.Println(encryptString, err)
}
