package zdpgo_password

import (
	"encoding/json"
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

// AesDump 将json对象加密为文件
func (p *Password) AesDump(filePath string, jsonObj interface{}) error {
	// 序列化JSON数据
	jsonBytes, err := json.Marshal(jsonObj)
	if err != nil {
		p.Log.Error("json序列化对象失败", "error", err)
		return err
	}

	// AES加密JSON数据
	encryptBytes, err := p.Aes.Encrypt(jsonBytes)
	if err != nil {
		p.Log.Error("AES加密数据失败", "error", err)
		return err
	}

	// 保存文件
	err = ioutil.WriteFile(filePath, encryptBytes, os.ModePerm)
	if err != nil {
		p.Log.Error("保存加密数据失败", "error", err)
		return err
	}

	return nil
}

// AesUpdate 更新加密文件内容
func (p *Password) AesUpdate(filePath string, jsonObj interface{}, newAesKey string) error {
	// 读取原本的内容
	err := p.AesLoad(filePath, jsonObj)
	if err != nil {
		p.Log.Error("读取原本的加密内容失败", "error", err)
		return err
	}

	// 更新key
	p.Aes.Config.Key = newAesKey

	// 重新加密保存
	err = p.AesDump(filePath, jsonObj)
	if err != nil {
		p.Log.Error("重新加密保存文件失败", "error", err)
		return err
	}

	// 返回
	return nil
}

// AesLoad 将密码文件加载为指定对象
func (p *Password) AesLoad(filePath string, jsonObj interface{}) error {
	// 读取密码文件
	fileBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		p.Log.Error("读取密码文件失败", "error", err)
		return err
	}

	// AES解密数据
	decryptedBytes, err := p.Aes.Decrypt(fileBytes)
	if err != nil {
		p.Log.Error("AES解密数据失败", "error", err)
		return err
	}

	// 读取JSON数据
	err = json.Unmarshal(decryptedBytes, jsonObj)
	if err != nil {
		p.Log.Error("解析JSON数据失败", "error", err)
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
