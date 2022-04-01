package zdpgo_password

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"
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

// EncryptSha1 此算法的加密结果能够被zdppy-python的RSA的decrypt方法解密
func (r *Rsa) EncryptSha1(dataToEncrypt string) (string, error) {
	// 获取公钥
	publicKeyByte, err := ioutil.ReadFile(r.Config.PublicKeyPath)
	if err != nil {
		return "", err
	}

	// 获取块
	block, _ := pem.Decode(publicKeyByte)

	// 解析公钥
	parseResultPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", err
	}

	// 转换公钥
	publicKey := parseResultPublicKey.(*rsa.PublicKey)

	// 执行加密
	encryptedBytes, err := rsa.EncryptOAEP(
		sha1.New(),
		rand.Reader,
		publicKey,
		[]byte(dataToEncrypt),
		nil)
	if err != nil {
		panic(err)
	}

	// 将加密结果转换为base64编码的字符串然后返回
	return Base64Encode(encryptedBytes), nil
}

// DecryptSha1 Sha1方式的RSA解密
func (r *Rsa) DecryptSha1(ciphertextBase64 string) (string, error) {
	// 获取私钥
	privateKeyByte, err := ioutil.ReadFile(r.Config.PrivateKeyPath)
	if err != nil {
		return "", err
	}

	// 获取块
	block, _ := pem.Decode(privateKeyByte)

	// 解析私钥
	privateKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

	// 解析base64的字符串
	b64Data, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return "", err
	}

	// 解密
	decryptedBytes, err := privateKey.Decrypt(rand.Reader, b64Data, &rsa.OAEPOptions{Hash: crypto.SHA1})
	if err != nil {
		return "", err
	}

	// 正确解密
	return string(decryptedBytes), nil
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
