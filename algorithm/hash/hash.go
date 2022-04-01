package hash

// Hash hash加密算法
type Hash struct {
	Md5    *Md5        // md5加密对象
	Hmac   *Hmac       // hmac加密对象
	Sha1   *Sha1       // sha1加密对象
	Sha256 *Sha256     // sha256加密对象
	Sha512 *Sha512     // sha512加密对象
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
	h.Md5 = NewMd5(config.Key)

	// hmac加密对象
	h.Hmac = NewHmac(config.Key, config.Algorithm)

	// sha1加密对象
	h.Sha1 = NewSha1(config.Key)

	// sha256加密对象
	h.Sha256 = NewSha256(config.Key)

	// sha512加密对象
	h.Sha512 = NewSha512(config.Key)

	return &h
}
