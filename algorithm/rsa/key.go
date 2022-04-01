package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
)

func (r *Rsa) GeneratePrivateKey() *rsa.PrivateKey {
	// GenerateKey函数使用随机数据生成器random生成一对具有指定字位数的RSA密钥
	// Reader是一个全局、共享的密码用强随机数生成器
	privateKey, err := rsa.GenerateKey(rand.Reader, r.Config.BitSize)
	if err != nil {
		panic(err)
	}

	// 保存私钥
	// 通过x509标准将得到的ras私钥序列化为ASN.1 的 DER编码字符串
	X509PrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)

	// 使用pem格式对x509输出的内容进行编码
	// 创建文件保存私钥
	privateFile, err := os.Create(r.Config.PrivateKeyPath)
	if err != nil {
		panic(err)
	}
	defer privateFile.Close()

	// 构建一个pem.Block结构体对象
	privateBlock := pem.Block{Type: "RSA Private Key", Bytes: X509PrivateKey}

	// 将数据保存到文件
	pem.Encode(privateFile, &privateBlock)

	return privateKey
}

func (r *Rsa) GeneratePublicKey(privateKey *rsa.PrivateKey) {
	// 保存公钥
	// 获取公钥的数据
	publicKey := privateKey.PublicKey

	// X509对公钥编码
	X509PublicKey, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		panic(err)
	}

	// pem格式编码
	// 创建用于保存公钥的文件
	publicFile, err := os.Create(r.Config.PublicKeyPath)
	if err != nil {
		panic(err)
	}
	defer publicFile.Close()

	// 创建一个pem.Block结构体对象
	publicBlock := pem.Block{Type: "RSA Public Key", Bytes: X509PublicKey}

	// 保存到文件
	pem.Encode(publicFile, &publicBlock)
}

// GenerateKey 生成RSA私钥和公钥，保存到文件中
// @param bitSize 证书大小
// @param privateKeyName 私钥文件名
// @param publicKeyName 公钥文件名
func (r *Rsa) GenerateKey() {
	privateKey := r.GeneratePrivateKey()
	r.GeneratePublicKey(privateKey)
}
