package zdpgo_password

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

// EncryptFile 加密文件
func (p *Password) EncryptFile(filePath string) error {
	// 获取加密文件路径，加密文件名
	encryptFilePath, encryptFileName, err := p.GetEncryptFileName(filePath)
	if err != nil {
		return err
	}

	// 使用AES加密文件内容
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}
	encryptData, err := p.Aes.Encrypt(data)
	if err != nil {
		return err
	}

	// 将加密文件内容写入到加密文件路径/加密文件名
	err = ioutil.WriteFile(fmt.Sprintf("%s/%s", encryptFilePath, encryptFileName), encryptData, 0644)
	if err != nil {
		return err
	}

	// 移除原本的文件
	err = os.Remove(filePath)
	if err != nil {
		return err
	}

	return nil
}

// DecryptFile 解密文件
func (p *Password) DecryptFile(filePath string) error {
	// 获取加密文件路径，加密文件名
	encryptFilePath, encryptFileName, err := p.GetEncryptFileName(filePath)
	if err != nil {
		return err
	}

	// 读取加密后的文件内容
	readData, err := ioutil.ReadFile(fmt.Sprintf("%s/%s", encryptFilePath, encryptFileName))
	if err != nil {
		return err
	}

	// 使用AES解密文件内容
	decryptData, err := p.Aes.Decrypt(readData)
	if err != nil {
		return err
	}

	// 将解密后的文件内容返回
	err = ioutil.WriteFile(filePath, decryptData, 0644)
	if err != nil {
		return err
	}

	// 移除原本的加密文件
	err = os.Remove(fmt.Sprintf("%s/%s", encryptFilePath, encryptFileName))
	if err != nil {
		return err
	}

	return nil
}

// EncryptFileNoChangeName 加密文件且不修改文件名
func (p *Password) EncryptFileNoChangeName(filePath string) error {
	// 读取加密后的文件内容
	readData, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	// 使用AES解密文件内容
	decryptData, err := p.Aes.Encrypt(readData)
	if err != nil {
		return err
	}

	// 将解密后的文件内容返回
	err = ioutil.WriteFile(filePath, decryptData, 0644)
	if err != nil {
		return err
	}

	return nil
}

// DecryptFileNoChangeName 解密文件且不修改文件名
func (p *Password) DecryptFileNoChangeName(filePath string) error {
	// 读取加密后的文件内容
	readData, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	// 使用AES解密文件内容
	decryptData, err := p.Aes.Decrypt(readData)
	if err != nil {
		return err
	}

	// 将解密后的文件内容返回
	err = ioutil.WriteFile(filePath, decryptData, 0644)
	if err != nil {
		return err
	}

	return nil
}

// ReadEncryptFile 读取加密文件的内容
func (p *Password) ReadEncryptFile(filePath string) (data []byte, err error) {
	// 获取加密文件路径，加密文件名
	encryptFilePath, encryptFileName, err := p.GetEncryptFileName(filePath)
	if err != nil {
		return
	}

	// 读取加密后的文件内容
	readData, err := ioutil.ReadFile(fmt.Sprintf("%s/%s", encryptFilePath, encryptFileName))
	if err != nil {
		return
	}

	// 使用AES解密文件内容
	data, err = p.Aes.Decrypt(readData)
	if err != nil {
		return
	}

	return
}

// DecryptFileWithEncryptName 根据加密文件名解密文件
func (p *Password) DecryptFileWithEncryptName(encryptFilePath string) error {
	// 获取原始的文件名
	encryptFileDir, fileName := filepath.Split(encryptFilePath)
	splitHex := p.Hex.EncodeString("zhangdapeng520")
	nameArr := strings.Split(fileName, splitHex)
	if nameArr == nil || len(nameArr) != 2 {
		return errors.New("文件名称不合法，无法正常解析")
	}
	hexName, err := p.Hex.DecodeString(nameArr[1])
	if err != nil {
		return err
	}

	// 读取加密后的文件内容
	readData, err := ioutil.ReadFile(encryptFilePath)
	if err != nil {
		return err
	}

	// 使用AES解密文件内容
	decryptData, err := p.Aes.Decrypt(readData)
	if err != nil {
		return err
	}

	// 将解密后的文件内容返回
	err = ioutil.WriteFile(fmt.Sprintf("%s/%s", encryptFileDir, hexName), decryptData, 0644)
	if err != nil {
		return err
	}

	// 移除原本的加密文件
	err = os.Remove(encryptFilePath)
	if err != nil {
		return err
	}

	return nil
}

// GetEncryptFileName 获取加密文件名
// @return decryptFilePath 加密文件路径
// @return decryptFileName 加密文件文件名
func (p *Password) GetEncryptFileName(filePath string) (encryptFilePath string, encryptFileName string, err error) {
	encryptFilePath, fileName := filepath.Split(filePath)
	encryptFileName, err = p.Hash.Md5.EncryptString(fmt.Sprintf("%s:%s:%s", filePath, encryptFilePath, fileName))
	if err != nil {
		return
	}

	// 加密文件名
	hexFileName := p.Hex.EncodeString(fileName)
	hexSplit := p.Hex.EncodeString("zhangdapeng520")

	// 得到最终的加密文件名称
	encryptFileName = fmt.Sprintf(".%s%s%s", encryptFileName, hexSplit, hexFileName)

	// 返回
	return
}
