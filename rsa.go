package zdpgo_password

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
)

type Rsa struct {
	Config *RsaConfig // Rsa配置对象
}

// NewRsa 新建Rsa对象
func NewRsa(config RsaConfig) *Rsa {
	r := Rsa{}

	// 初始化配置
	r.Config = &config
	if config.PrivateKeyPath == "" {

	}

	return &r
}

func (r *Rsa) GeneratePrivateKey(bitSize int, name string) *rsa.PrivateKey {
	// GenerateKey函数使用随机数据生成器random生成一对具有指定字位数的RSA密钥
	// Reader是一个全局、共享的密码用强随机数生成器
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		panic(err)
	}

	// 保存私钥
	// 通过x509标准将得到的ras私钥序列化为ASN.1 的 DER编码字符串
	X509PrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)

	// 使用pem格式对x509输出的内容进行编码
	// 创建文件保存私钥
	privateFile, err := os.Create(name)
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

func (r *Rsa) GeneratePublicKey(privateKey *rsa.PrivateKey, name string) {
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
	publicFile, err := os.Create(name)
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
func (r *Rsa) GenerateKey(bitSize int, privateKeyName, publicKeyName string) {
	privateKey := r.GeneratePrivateKey(bitSize, privateKeyName)
	r.GeneratePublicKey(privateKey, publicKeyName)
}

//Encrypt RSA加密
// @param plainText 要加密的数据
// @param publicKeyPath 公钥匙文件地址
func (r *Rsa) Encrypt(plainText []byte, publicKeyPath string) []byte {
	//打开文件
	file, err := os.Open(publicKeyPath)
	if err != nil {
		panic(err)
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
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, plainText)
	if err != nil {
		panic(err)
	}

	// 返回密文
	return cipherText
}

// Decrypt RSA解密
// @param cipherText 需要解密的byte数据
// @param privateKeyPath 私钥文件路径
func (r *Rsa) Decrypt(cipherText []byte, privateKeyPath string) []byte {
	//打开文件
	file, err := os.Open(privateKeyPath)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	// 获取文件内容
	info, _ := file.Stat()
	buf := make([]byte, info.Size())
	file.Read(buf)

	// pem解码
	block, _ := pem.Decode(buf)

	// X509解码
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	// 对密文进行解密
	plainText, _ := rsa.DecryptPKCS1v15(rand.Reader, privateKey, cipherText)

	// 返回明文
	return plainText
}
