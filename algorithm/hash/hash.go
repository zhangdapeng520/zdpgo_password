package hash

// Hash hash加密算法
type Hash struct {
	Md5    *Md5        // md5加密对象
	Hmac   *Hmac       // hmac加密对象
	Config *HashConfig // 配置对象
}

// New 创建hash加密算法的实例
func New(config HashConfig) *Hash {
	h := Hash{}

	// 初始化配置
	if config.Key == "" || len(config.Key)%16 != 0 {
		config.Key = "_ZhangDapeng520%"
	}
	if config.Algorithm == "" {
		config.Algorithm = "sha256"
	}
	h.Config = &config

	// md5加密对象
	h.Md5 = NewMd5()

	// hmac加密对象
	h.Hmac = NewHmac(config.Key, config.Algorithm)

	return &h
}
