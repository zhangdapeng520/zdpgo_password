package hash

import (
	"fmt"
	"testing"
)

func getSha512() *Sha512 {
	return NewSha512("abc")
}

func TestSha512_Encrypt(t *testing.T) {
	s := getSha512()
	data := "abc"

	// 加密
	encrypt, err := s.Encrypt([]byte(data))
	fmt.Println(encrypt, err)

	// 解密
	encryptString, err := s.EncryptString(data)
	fmt.Println(encryptString, err)
}
