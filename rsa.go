package zdpgo_password

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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

	// 返回
	return &r
}

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

//Encrypt RSA加密
// @param plainText 要加密的数据
// @param publicKeyPath 公钥匙文件地址
func (r *Rsa) Encrypt(plainText []byte) string {
	//打开文件
	file, err := os.Open(r.Config.PublicKeyPath)
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

	// 转换为base64
	b64Data := Base64Encode(cipherText)

	// 返回密文
	return b64Data
}

// Decrypt RSA解密
// @param cipherText 需要解密的byte数据
// @param privateKeyPath 私钥文件路径
func (r *Rsa) Decrypt(b64Data string) string {
	// base64解码
	cipherText := Base64Decode(b64Data)

	//打开文件
	file, err := os.Open(r.Config.PrivateKeyPath)
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
	plainText, _ := rsa.DecryptPKCS1v15(rand.Reader, privateKey, []byte(cipherText))

	// 返回明文
	return string(plainText)
}

// Sign 签名：采用sha1算法进行签名并输出为hex格式（私钥PKCS8格式）
func (r *Rsa) Sign(plainText string) string {
	// 打开文件获取私匙
	file, err := os.Open(r.Config.PrivateKeyPath)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	fileInfo, err := file.Stat()
	if err != nil {
		panic(err)
	}
	buf := make([]byte, fileInfo.Size())
	file.Read(buf)

	// 将私匙反pem化
	block, _ := pem.Decode(buf)

	// 将私匙反X509序列化
	privkey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	// 创建指定哈希函数的Hash接口
	myHash := sha256.New()

	// 将明文写入myHash结构体
	myHash.Write([]byte(plainText))

	// 获得明文的散列值
	hashText := myHash.Sum(nil)

	// 将明文的散列值采用RSA私匙进行签名
	cipher, err := rsa.SignPKCS1v15(rand.Reader, privkey, crypto.SHA256, hashText)
	if err != nil {
		panic(err)
	}

	// 返回签名
	b64Data := Base64Encode(cipher)

	return b64Data
}

// Verify 验签：对采用sha1算法进行签名后转base64格式的数据进行验签
func (r *Rsa) Verify(originalData, signData string) bool {
	// 打开文件获取公匙
	file, err := os.Open(r.Config.PublicKeyPath)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	fileInfo, err := file.Stat()
	if err != nil {
		panic(err)
	}
	buf := make([]byte, fileInfo.Size())
	file.Read(buf)

	// 将公匙反pem码化
	block, _ := pem.Decode(buf)

	// 将公匙反x509序列化
	pubInterface, _ := x509.ParsePKIXPublicKey(block.Bytes)

	// 执行公匙的类型断言
	publicKey := pubInterface.(*rsa.PublicKey)

	// 创建hash接口，指定采用的哈希函数
	myHash := sha256.New()

	// 向myHash中写入内容
	myHash.Write([]byte(originalData))

	// 生成明文的散列值
	hashText := myHash.Sum(nil)

	// 对数字签名后的内容进行解密
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashText, []byte(signData))

	// 返回校验结果
	return err != nil
}
