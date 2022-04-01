package zdpgo_password

import (
	"github.com/zhangdapeng520/zdpgo_log"
	"github.com/zhangdapeng520/zdpgo_password/algorithm/aes"
	"github.com/zhangdapeng520/zdpgo_password/algorithm/ecc"
	"github.com/zhangdapeng520/zdpgo_password/algorithm/hash"
	"github.com/zhangdapeng520/zdpgo_password/algorithm/rsa"
)

// Password 密码加密核心对象
type Password struct {
	log    *zdpgo_log.Log  // 日志对象
	config *PasswordConfig // 配置对象
	Aes    *aes.Aes        // AES加密核心对象
	Rsa    *rsa.Rsa        // RSA加密核心对象
	Hash   *hash.Hash      // HASH加密核心对象
	Ecc    *ecc.Ecc        // ECC加密核心对象
}

// New 创建加密对象
func New(config PasswordConfig) *Password {
	// 创建密码对象
	p := Password{}

	// 生成日志对象
	if config.LogFilePath == "" {
		config.LogFilePath = "zdpgo_password.log"
	}
	logConfig := zdpgo_log.LogConfig{
		Debug: config.Debug,
		Path:  config.LogFilePath,
	}
	l := zdpgo_log.New(logConfig)
	p.log = l

	// 生成配置
	p.config = &config

	// 创建AES加密对象
	p.Aes = aes.NewAes(aes.AesConfig{
		Key:       config.Aes.Key,
		BlockSize: config.Aes.BlockSize,
	})

	// 创建RSA加密对象
	p.Rsa = rsa.NewRsa(rsa.RsaConfig{
		PrivateKeyPath: config.Rsa.PrivateKeyPath,
		PublicKeyPath:  config.Rsa.PublicKeyPath,
		BitSize:        config.Rsa.BitSize,
	})

	// 创建HASH加密对象
	p.Hash = hash.NewHash(hash.HashConfig{
		Key:       config.Hash.Key,
		Algorithm: config.Hash.Algorithm,
	})

	// 创建ECC加密对象
	p.Ecc = ecc.NewEcc()

	// 返回密码对象
	return &p
}
