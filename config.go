package zdpgo_password

import (
	"github.com/zhangdapeng520/zdpgo_password/core/algorithm/aes"
	"github.com/zhangdapeng520/zdpgo_password/core/algorithm/hash"
	"github.com/zhangdapeng520/zdpgo_password/core/algorithm/rsa"
)

// PasswordConfig 密码配置对象
type PasswordConfig struct {
	Debug       bool            // 是否为debug模式
	LogFilePath string          // 日志路径
	Aes         aes.AesConfig   `yaml:"aes" json:"aes"`   // AES加密核心配置
	Rsa         rsa.RsaConfig   `yaml:"rsa" json:"rsa"`   // RSA加密核心配置
	Hash        hash.HashConfig `yaml:"hash" json:"hash"` // HASH加密核心配置
}
