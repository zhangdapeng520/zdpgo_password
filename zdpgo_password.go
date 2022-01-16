package zdpgo_password

import (
	"crypto/md5"
	"encoding/hex"
	"github.com/zhangdapeng520/zdpgo_log"
	"io"
)

// 密码加密核心对象
type ZdpPassword struct {
	log    *zdpgo_log.Log    // 日志对象
	config ZdpPasswordConfig // 配置对象
}

// 配置对象
type ZdpPasswordConfig struct {
	Debug       bool   // 是否为debug模式
	LogFilePath string // 日志路径
}

// 创建加密对象
func New(config ZdpPasswordConfig) *ZdpPassword {
	p := ZdpPassword{}

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
	p.config = config
	return &p
}

// Make 密码加密
// @param password 用户要加密的密码
func (p *ZdpPassword) Make(password string) string {
	return MakePassword(password)
}

// Check 检查密码是否正确
// @param userPassword 用户输入的密码
// @param dataPassword 数据库中加密的密码
func (p *ZdpPassword) Check(userPassword, dataPassword string) bool {
	return CheckPassword(userPassword, dataPassword)
}

// Md5 生成md5加密字符串
// @param content 要加密的内容
func (p *ZdpPassword) Md5(content string) string {
	m := md5.New()
	_, _ = io.WriteString(m, content)
	return hex.EncodeToString(m.Sum(nil))
}

// Md5Check 生成md5加密字符串
// @param content 要加密的内容
// @param md5Content md5加密后的内容
func (p *ZdpPassword) Md5Check(content string, md5Content string) bool {
	return p.Md5(content) == md5Content
}
