package zdpgo_password

import (
	"github.com/zhangdapeng520/zdpgo_password/aes"
	"github.com/zhangdapeng520/zdpgo_password/hash"
	"github.com/zhangdapeng520/zdpgo_password/hex"
	"github.com/zhangdapeng520/zdpgo_password/zurl"
)

// Password 密码加密核心对象
type Password struct {
	Config   *Config           // 配置对象
	Aes      *aes.Aes          // AES加密核心对象
	Hash     *hash.Hash        // HASH加密核心对象
	Url      *zurl.Url         // URL编码解码核心对象
	Hex      *hex.Hex          // 十六进制编码解码
	BytesMap map[string][]byte // 用于存放bytes数组的字典
}

func New() *Password {
	return NewWithConfig(&Config{})
}

// NewWithConfig 创建加密对象
func NewWithConfig(config *Config) *Password {
	// 创建密码对象
	p := Password{
		BytesMap: make(map[string][]byte),
	}

	// 生成配置
	if config.KeyPath == "" {
		config.KeyPath = ".zdpgo_password_keys"
	}
	p.Config = config

	// 创建AES加密对象
	p.Aes = aes.NewAes(aes.AesConfig{
		Key:       config.Aes.Key,
		BlockSize: config.Aes.BlockSize,
	})

	// 创建HASH加密对象
	p.Hash = hash.NewHash(hash.HashConfig{
		Key:       config.Hash.Key,
		Algorithm: config.Hash.Algorithm,
	})

	// 创建URL核心对象
	p.Url = zurl.NewUrl()

	// 创建HEX核心对象
	p.Hex = hex.NewHex()

	// 返回密码对象
	return &p
}
