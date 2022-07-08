package zdpgo_password

import (
	"github.com/zhangdapeng520/zdpgo_password/aes"
	"github.com/zhangdapeng520/zdpgo_password/hash"
)

// Config 密码配置对象
type Config struct {
	Aes     aes.AesConfig   `yaml:"aes" json:"aes"`   // AES加密核心配置
	Hash    hash.HashConfig `yaml:"hash" json:"hash"` // HASH加密核心配置
	KeyPath string          `yaml:"key_path" json:"key_path"`
}
