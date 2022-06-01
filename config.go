package zdpgo_password

import (
	"github.com/zhangdapeng520/zdpgo_password/core/algorithm/aes"
	"github.com/zhangdapeng520/zdpgo_password/core/algorithm/hash"
	"github.com/zhangdapeng520/zdpgo_password/core/algorithm/rsa"
)

// Config 密码配置对象
type Config struct {
	Debug       bool            // 是否为debug模式
	LogFilePath string          // 日志路径
	Aes         aes.AesConfig   `yaml:"aes" json:"aes"`   // AES加密核心配置
	Rsa         rsa.RsaConfig   `yaml:"rsa" json:"rsa"`   // RSA加密核心配置
	Hash        hash.HashConfig `yaml:"hash" json:"hash"` // HASH加密核心配置
	KeyPath     string          `yaml:"key_path" json:"key_path"`
	EccKey      Key             `yaml:"ecc_key" json:"ecc_key"` // ECC秘钥
}

type Key struct {
	PrivateKeyPrefix   string `yaml:"private_key_prefix" json:"private_key_prefix"`
	PublicKeyPrefix    string `yaml:"public_key_prefix" json:"public_key_prefix"`
	PrivateKeyFileName string `yaml:"private_key_file_name" json:"private_key_file_name"`
	PublicKeyFileName  string `yaml:"public_key_file_name" json:"public_key_file_name"`
}
