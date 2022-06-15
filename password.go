package zdpgo_password

import (
	"github.com/zhangdapeng520/zdpgo_log"
	aes2 "github.com/zhangdapeng520/zdpgo_password/core/algorithm/aes"
	hash2 "github.com/zhangdapeng520/zdpgo_password/core/algorithm/hash"
	rsa2 "github.com/zhangdapeng520/zdpgo_password/core/algorithm/rsa"
	"github.com/zhangdapeng520/zdpgo_password/core/hex"
	"github.com/zhangdapeng520/zdpgo_password/core/zurl"
)

var (
	Log *zdpgo_log.Log
)

// Password 密码加密核心对象
type Password struct {
	Config *Config     // 配置对象
	Aes    *aes2.Aes   // AES加密核心对象
	Rsa    *rsa2.Rsa   // RSA加密核心对象
	Hash   *hash2.Hash // HASH加密核心对象
	Ecc    *Ecc        // ECC加密核心对象
	Url    *zurl.Url   // URL编码解码核心对象
	Hex    *hex.Hex    // 十六进制编码解码
}

func New(log *zdpgo_log.Log) *Password {
	return NewWithConfig(&Config{}, log)
}

// NewWithConfig 创建加密对象
func NewWithConfig(config *Config, log *zdpgo_log.Log) *Password {
	// 创建密码对象
	p := Password{}

	// 生成日志对象
	p.SetLog(log)

	// 生成配置
	if config.KeyPath == "" {
		config.KeyPath = ".zdpgo_password_keys"
	}
	if config.EccKey.PrivateKeyPrefix == "" {
		config.EccKey.PrivateKeyPrefix = " ZDPGO_PASSWORD ECC PRIVATE KEY "
	}
	if config.EccKey.PublicKeyPrefix == "" {
		config.EccKey.PublicKeyPrefix = " ZDPGO_PASSWORD ECC PUBLIC KEY "
	}
	if config.EccKey.PrivateKeyFileName == "" {
		config.EccKey.PrivateKeyFileName = "ecc_private.pem"
	}
	if config.EccKey.PublicKeyFileName == "" {
		config.EccKey.PublicKeyFileName = "ecc_public.pem"
	}
	p.Config = config

	// 创建AES加密对象
	p.Aes = aes2.NewAes(aes2.AesConfig{
		Key:       config.Aes.Key,
		BlockSize: config.Aes.BlockSize,
	})

	// 创建RSA加密对象
	p.Rsa = rsa2.NewRsa(rsa2.RsaConfig{
		PrivateKeyPath: config.Rsa.PrivateKeyPath,
		PublicKeyPath:  config.Rsa.PublicKeyPath,
		BitSize:        config.Rsa.BitSize,
	})

	// 创建HASH加密对象
	p.Hash = hash2.NewHash(hash2.HashConfig{
		Key:       config.Hash.Key,
		Algorithm: config.Hash.Algorithm,
	})

	// 创建ECC加密对象
	p.Ecc = p.GetEcc()

	// 创建URL核心对象
	p.Url = zurl.NewUrl()

	// 创建HEX核心对象
	p.Hex = hex.NewHex()

	// 返回密码对象
	return &p
}

// SetLog 设置日志
func SetLog(log *zdpgo_log.Log) {
	Log = log
}

// SetLog 设置日志
func (p *Password) SetLog(log *zdpgo_log.Log) {
	SetLog(log)
}

// GetEcc 获取ECC加密对象
func (p *Password) GetEcc() *Ecc {
	e := &Ecc{
		Config: p.Config,
	}

	// 私钥和公钥可以直接指定
	if p.Config.EccKey.PrivateKey != nil && len(p.Config.EccKey.PrivateKey) > 0 {
		e.privateKey = p.Config.EccKey.PrivateKey
	}
	if p.Config.EccKey.PublicKey != nil && len(p.Config.EccKey.PublicKey) > 0 {
		e.publicKey = p.Config.EccKey.PublicKey
	}

	// 没有指定，就自己生成
	if (e.privateKey == nil || len(e.privateKey) == 0) && (e.publicKey == nil || len(e.publicKey) == 0) {
		err := e.InitKey()
		if err != nil {
			Log.Error("初始化公钥和私钥失败")
		}
	}

	// 返回
	return e
}
