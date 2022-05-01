package zdpgo_password

import (
	"fmt"
	"testing"
)

func TestPassword_getEncryptFileName(t *testing.T) {
	p := getPassword()
	files := []string{
		"a/b/c/d/ttt.txt",
		"c:\\a\\b\\c\\ttt.txt",
	}
	for _, file := range files {
		encryptFilePath, encryptFileName, err := p.getEncryptFileName(file)
		fmt.Println(encryptFilePath, encryptFileName, err)
	}
}

func TestPassword_EncryptFile(t *testing.T) {
	p := getPassword()
	files := []string{
		"test/test.txt",
		"test/test.exe",
	}
	for _, file := range files {
		err := p.EncryptFile(file)
		if err != nil {
			panic(err)
		}
	}
}

func TestPassword_DecryptFile(t *testing.T) {
	p := getPassword()
	files := []string{
		"test/test.txt",
		"test/test.exe",
	}
	for _, file := range files {
		err := p.DecryptFile(file)
		if err != nil {
			panic(err)
		}
	}
}

func TestPassword_DecryptFileWithEncryptName(t *testing.T) {
	p := getPassword()
	files := []string{
		"test/.5f5a68616e67446170656e6735323025a33e93c4ca75480e3aa762b48c959c157a68616e67646170656e67353230746573742e747874",
		"test/.5f5a68616e67446170656e67353230259fccae81034bc88b748e1034e3dbaf4b7a68616e67646170656e67353230746573742e657865",
	}
	for _, file := range files {
		err := p.DecryptFileWithEncryptName(file)
		if err != nil {
			panic(err)
		}
	}
}
