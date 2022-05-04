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
		encryptFilePath, encryptFileName, err := p.GetEncryptFileName(file)
		fmt.Println(encryptFilePath, encryptFileName, err)
	}
}

func TestPassword_EncryptFile(t *testing.T) {
	p := getPassword()
	files := []string{
		"test/test.txt",
		"test/test.go",
	}
	for _, file := range files {
		err := p.EncryptFile(file)
		if err != nil {
			panic(err)
		}
	}
}

func TestPassword_EncryptFileNoChangeName(t *testing.T) {
	p := getPassword()
	files := []string{
		"test/test.txt",
	}
	for _, file := range files {
		err := p.EncryptFileNoChangeName(file)
		if err != nil {
			panic(err)
		}
	}
}

func TestPassword_DecryptFileNoChangeName(t *testing.T) {
	p := getPassword()
	files := []string{
		"test/test.txt",
	}
	for _, file := range files {
		err := p.DecryptFileNoChangeName(file)
		if err != nil {
			panic(err)
		}
	}
}

func TestPassword_DecryptFile(t *testing.T) {
	p := getPassword()
	files := []string{
		"test/test.txt",
		"test/test.go",
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
		"test/.5f5a68616e67446170656e6735323025043f7f70c2ce9cbdb9f08e1b3fef04dc7a68616e67646170656e67353230746573742e676f",
	}
	for _, file := range files {
		err := p.DecryptFileWithEncryptName(file)
		if err != nil {
			panic(err)
		}
	}
}
