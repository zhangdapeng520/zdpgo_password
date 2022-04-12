package zdpgo_password

import (
	"github.com/zhangdapeng520/zdpgo_log"
	aes2 "github.com/zhangdapeng520/zdpgo_password/core/algorithm/aes"
	"github.com/zhangdapeng520/zdpgo_password/core/algorithm/ecc"
	hash2 "github.com/zhangdapeng520/zdpgo_password/core/algorithm/hash"
	rsa2 "github.com/zhangdapeng520/zdpgo_password/core/algorithm/rsa"
	"github.com/zhangdapeng520/zdpgo_password/core/hex"
	"github.com/zhangdapeng520/zdpgo_password/core/zurl"
)

// Password 密码加密核心对象
type Password struct {
	log    *zdpgo_log.Log  // 日志对象
	config *PasswordConfig // 配置对象
	Aes    *aes2.Aes       // AES加密核心对象
	Rsa    *rsa2.Rsa       // RSA加密核心对象
	Hash   *hash2.Hash     // HASH加密核心对象
	Ecc    *ecc.Ecc        // ECC加密核心对象
	Url    *zurl.Url       // URL编码解码核心对象
	Hex    *hex.Hex        // 十六进制编码解码
}

// New 创建加密对象
func New(config PasswordConfig) *Password {
	// 创建密码对象
	p := Password{}

	// 生成日志对象
	if config.LogFilePath == "" {
		config.LogFilePath = "zdpgo_password.log"
	}
	logConfig := zdpgo_log.Config{
		Debug:       config.Debug,
		LogFilePath: config.LogFilePath,
	}
	l := zdpgo_log.New(logConfig)
	p.log = l

	// 生成配置
	p.config = &config

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
	p.Ecc = ecc.NewEcc()

	// 创建URL核心对象
	p.Url = zurl.NewUrl()

	// 创建HEX核心对象
	p.Hex = hex.NewHex()

	// 返回密码对象
	return &p
}
