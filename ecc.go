package zdpgo_password

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"github.com/zhangdapeng520/zdpgo_log"
	"github.com/zhangdapeng520/zdpgo_password/goEncrypt"
	"io/ioutil"
	"os"
	"path"
	"strings"
)

/*
@Time : 2022/6/1 16:34
@Author : 张大鹏
@File : ecc.go
@Software: Goland2021.3.1
@Description:
*/

type Ecc struct {
	Config     *Config
	Log        *zdpgo_log.Log
	privateKey []byte
	publicKey  []byte
}

// InitKey 初始化key
func (e *Ecc) InitKey() error {
	var (
		privateKeyFilePath = path.Join(e.Config.KeyPath, e.Config.EccKey.PrivateKeyFileName)
		publicKeyFilePath  = path.Join(e.Config.KeyPath, e.Config.EccKey.PublicKeyFileName)
		err                error
	)

	// 创建key目录
	if !Exists(e.Config.KeyPath) {
		err = os.MkdirAll(e.Config.KeyPath, os.ModePerm)
		if err != nil {
			e.Log.Error("创建功key存放目录失败", "error", err)
			return err
		}
	}

	// 设置公钥和私钥数据
	if Exists(privateKeyFilePath) && Exists(publicKeyFilePath) {
		err = e.SetKeyData(privateKeyFilePath, publicKeyFilePath)
		if err != nil {
			e.Log.Error("设置公钥和私钥数据失败", "error", err)
			return err
		}
		return nil
	}

	// 创建私钥
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		e.Log.Error("创建私钥失败", "error", err)
		return err
	}

	// 序列化私钥
	x509PrivateKey, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		e.Log.Error("序列化私钥失败", "error", err)
		return err
	}

	// 创建私钥文件
	block := pem.Block{
		Type:  e.Config.EccKey.PrivateKeyPrefix,
		Bytes: x509PrivateKey,
	}
	file, err := os.Create(privateKeyFilePath)
	if err != nil {
		e.Log.Error("创建私钥文件失败", "error", err)
		return err
	}
	defer file.Close()
	if err = pem.Encode(file, &block); err != nil {
		e.Log.Error("写入私钥数据失败", "error", err)
		return err
	}

	// 序列化公钥
	x509PublicKey, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		e.Log.Error("序列化公钥失败", "error", err)
		return err
	}

	// 创建公钥文件
	publicBlock := pem.Block{
		Type:  e.Config.EccKey.PublicKeyPrefix,
		Bytes: x509PublicKey,
	}
	publicFile, err := os.Create(publicKeyFilePath)
	if err != nil {
		e.Log.Error("创建公钥文件失败", "error", err)
		return err
	}
	defer publicFile.Close()

	if err = pem.Encode(publicFile, &publicBlock); err != nil {
		e.Log.Error("写入公钥数据失败", "error", err)
		return err
	}

	// 设置公钥和私钥数据
	err = e.SetKeyData(privateKeyFilePath, publicKeyFilePath)
	if err != nil {
		e.Log.Error("设置公钥和私钥数据失败", "error", err)
		return err
	}

	// 返回
	return nil
}

// SetKeyData 设置公钥和私钥数据
func (e *Ecc) SetKeyData(privateKeyFilePath, publicKeyFilePath string) error {
	var err error
	e.privateKey, err = ioutil.ReadFile(privateKeyFilePath)
	if err != nil {
		e.Log.Error("读取私钥文件失败", "error", err, "file", privateKeyFilePath)
		return err
	}

	e.publicKey, err = ioutil.ReadFile(publicKeyFilePath)
	if err != nil {
		e.Log.Error("读取公钥文件失败", "error", err, "file", publicKeyFilePath)
		return err
	}

	return nil
}

// Encrypt 加密数据
func (e *Ecc) Encrypt(data []byte) ([]byte, error) {
	// 读取公钥
	if e.publicKey == nil || len(e.privateKey) == 0 {
		publicKey, err := ioutil.ReadFile(path.Join(e.Config.KeyPath, e.Config.EccKey.PublicKeyFileName))
		if err != nil {
			e.Log.Error("读取公钥失败", "error", err)
			return nil, err
		}
		e.publicKey = publicKey
	}

	// 加密
	cryptText, err := goEncrypt.EccEncrypt(data, e.publicKey)
	if err != nil {
		e.Log.Error("ECC加密数据失败", "error", err)
		return nil, err
	}

	// 返回加密后的数据
	return cryptText, nil
}

// Decrypt 解密数据
func (e *Ecc) Decrypt(cryptData []byte) ([]byte, error) {
	// 读取私钥
	if e.privateKey == nil || len(e.publicKey) == 0 {
		privateKey, err := ioutil.ReadFile(path.Join(e.Config.KeyPath, e.Config.EccKey.PrivateKeyFileName))
		if err != nil {
			e.Log.Error("读取私钥失败", "error", err)
			return nil, err
		}
		e.privateKey = privateKey
	}

	// 解密
	data, err := goEncrypt.EccDecrypt(cryptData, e.privateKey)
	if err != nil {
		e.Log.Error("ECC解密数据失败", "error", err)
		return nil, err
	}

	// 返回解密后的数据
	return data, nil
}

// Sign 对数据进行签名
func (e *Ecc) Sign(data []byte) ([]byte, error) {
	// 读取私钥
	if e.privateKey == nil || len(e.privateKey) == 0 {
		privateKey, err := ioutil.ReadFile(path.Join(e.Config.KeyPath, e.Config.EccKey.PrivateKeyFileName))
		if err != nil {
			e.Log.Error("读取私钥失败", "error", err)
			return nil, err
		}
		e.privateKey = privateKey
	}

	// 获取结果和签名
	resultData, signData, err := goEncrypt.EccSign(data, e.privateKey)
	if err != nil {
		e.Log.Error("获取结果和签名失败", "error", err)
		return nil, err
	}

	// 拼接结果和签名
	resultStr := base64.StdEncoding.EncodeToString(resultData)
	signStr := base64.StdEncoding.EncodeToString(signData)
	result := resultStr + "zhangdapeng520" + signStr

	// 返回字节数组
	return []byte(result), nil
}

// Verify 对数据进行校验
func (e *Ecc) Verify(originData, signData []byte) bool {
	// 读取私钥
	if e.publicKey == nil || len(e.publicKey) == 0 {
		publicKey, err := ioutil.ReadFile(path.Join(e.Config.KeyPath, e.Config.EccKey.PrivateKeyFileName))
		if err != nil {
			e.Log.Error("读取私钥失败", "error", err)
			return false
		}
		e.publicKey = publicKey
	}

	// 先拆分签名数据
	signStr := string(signData)
	tempData := strings.Split(signStr, "zhangdapeng520")
	if len(tempData) != 2 {
		e.Log.Error("非法的签名数据")
		return false
	}

	// base64解码数据
	resultStr, signStr := tempData[0], tempData[1]
	resultData, err := base64.StdEncoding.DecodeString(resultStr)
	if err != nil {
		e.Log.Error("解码结果字符串失败", "error", err)
		return false
	}

	realSignData, err := base64.StdEncoding.DecodeString(signStr)
	if err != nil {
		e.Log.Error("解码签名字符串失败", "error", err)
		return false
	}

	// 校验签名
	result := goEncrypt.EccVerifySign(originData, e.publicKey, resultData, realSignData)

	// 返回校验结果
	return result
}
