package aes

// 密码学中的高级加密标准（Advanced Encryption Standard，AES），又称Rijndael加密法，是美国联邦政府采用的一种区块加密标准。
// 这个标准用来替代原先的DES（Data Encryption Standard），已经被多方分析且广为全世界所使用。
// AES中常见的有三种解决方案，分别为AES-128、AES-192和AES-256。
// 如果采用真正的128位加密技术甚至256位加密技术，蛮力攻击要取得成功需要耗费相当长的时间。

// AES 有五种加密模式：
// 电码本模式（Electronic Codebook Book (ECB)）
// 密码分组链接模式（Cipher Block Chaining (CBC)）
// 计算器模式（Counter (CTR)）
// 密码反馈模式（Cipher FeedBack (CFB)）
// 输出反馈模式（Output FeedBack (OFB)）

type Aes struct {
	config *AesConfig // aes的配置
	Ecb    *AesEcb    // ECB模式加密对象
	Cbc    *AesCbc    // CBC模式加密对象
	Ctr    *AesCrt    // CTR模式加密对象
	Cfb    *AesCfb    // CFB模式加密对象
	Ofb    *AesOfb    // CFB模式加密对象
	Gcm    *AesGcm    // GCM模式加密对象

	// 默认的加密解密方法GCM
	Encrypt       func(data []byte) ([]byte, error)
	Decrypt       func(data []byte) ([]byte, error)
	EncryptString func(data string) (string, error)
	DecryptString func(data string) (string, error)
}

func NewAes(config AesConfig) *Aes {
	a := Aes{}

	// 初始化配置
	if config.Key == "" {
		config.Key = "_ZhangDapeng520%"
	}
	if config.BlockSize == 0 {
		config.BlockSize = 16
	}
	a.config = &config

	// 加密对象
	a.Ecb = NewAesEcb(config.Key)
	a.Cbc = NewAesCbc(config.Key)
	a.Ctr = NewAesCrt(config.Key)
	a.Cfb = NewAesCfb(config.Key)
	a.Ofb = NewAesOfb(config.Key)
	a.Gcm = NewAesGcm(config.Key)

	// 默认加密方法
	a.Encrypt = a.Gcm.Encrypt
	a.Decrypt = a.Gcm.Decrypt
	a.EncryptString = a.Gcm.EncryptString
	a.DecryptString = a.Gcm.DecryptString

	// 返回
	return &a
}
