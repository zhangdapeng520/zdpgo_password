package zdpgo_password

// EncryptInterface 密码加密接口
type EncryptInterface interface {
	Encrypt(data []byte) ([]byte, error) // 密码加密
}

// DecryptInterface 密码解密接口
type DecryptInterface interface {
	Decrypt(data []byte) ([]byte, error) // 密码解密
}

// PasswordInterface 字节数据密码接口
type PasswordInterface interface {
	EncryptInterface
	DecryptInterface
}

// EncryptStringInterface 字符串加密接口
type EncryptStringInterface interface {
	EncryptString(data string) (string, error) // 密码加密
}

// DecryptStringInterface 字符串解密接口
type DecryptStringInterface interface {
	DecryptString(data string) (string, error) // 密码解密
}

// PasswordStringInterface 字符串数据密码接口
type PasswordStringInterface interface {
	EncryptStringInterface
	DecryptStringInterface
}
