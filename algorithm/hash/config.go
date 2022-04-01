package hash

// HashConfig hash算法加密配置
type HashConfig struct {
	Key       string `json:"key" yaml:"key"`             // 加密的key
	Algorithm string `json:"algorithm" yaml:"algorithm"` // 加密的算法
}
