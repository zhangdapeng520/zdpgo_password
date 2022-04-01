package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
)

type Rsa struct {
	Config *RsaConfig // Rsa配置对象
	Sha1   *RsaSha1   // sha1加密方式
}

// NewRsa 新建Rsa对象
func NewRsa(config RsaConfig) *Rsa {
	r := Rsa{}

	// 初始化配置
	if config.PrivateKeyPath == "" {
		config.PrivateKeyPath = "private.pem"
	}
	if config.PublicKeyPath == "" {
		config.PublicKeyPath = "public.pem"
	}
	if config.BitSize == 0 {
		config.BitSize = 2048
	}
	r.Config = &config

	// 加密对象
	r.Sha1 = NewRsaSha1(config)

	// 返回
	return &r
}

//Encrypt RSA加密
// @param plainText 要加密的数据
// @param publicKeyPath 公钥匙文件地址
func (r *Rsa) Encrypt(data []byte) ([]byte, error) {
	//打开文件
	file, err := os.Open(r.Config.PublicKeyPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// 读取文件的内容
	info, _ := file.Stat()
	buf := make([]byte, info.Size())
	file.Read(buf)

	// pem解码
	block, _ := pem.Decode(buf)

	// x509解码
	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	// 类型断言
	publicKey := publicKeyInterface.(*rsa.PublicKey)

	// 对明文进行加密
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, data)
	if err != nil {
		return nil, err
	}

	// 返回加密后的数据
	return cipherText, nil
}

// Decrypt RSA解密
// @param cipherText 需要解密的byte数据
// @param privateKeyPath 私钥文件路径
func (r *Rsa) Decrypt(data []byte) ([]byte, error) {
	//打开文件
	file, err := os.Open(r.Config.PrivateKeyPath)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	// 获取文件内容
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}

	buf := make([]byte, info.Size())
	_, err = file.Read(buf)
	if err != nil {
		return nil, err
	}

	// pem解码
	block, _ := pem.Decode(buf)

	// X509解码
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	// 对密文进行解密
	plainText, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, data)
	if err != nil {
		return nil, err
	}

	// 返回明文
	return plainText, nil
}
func (r *Rsa) EncryptString(data string) (string, error) {
	// 获取加密的字节数组
	encrypt, err := r.Encrypt([]byte(data))
	if err != nil {
		return "", err
	}

	// 将加密结果转换为base64编码的字符串然后返回
	return base64.StdEncoding.EncodeToString(encrypt), nil
}

// DecryptString Sha1方式的RSA解密
func (r *Rsa) DecryptString(data string) (string, error) {
	// 解析base64的字符串
	b64Data, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}

	// 获取解密字节数组
	decrypt, err := r.Decrypt(b64Data)
	if err != nil {
		return "", err
	}

	// 返回解密字符串
	return string(decrypt), nil
}
