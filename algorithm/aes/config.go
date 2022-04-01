package aes

type AesConfig struct {
	Key       string `yaml:"key" json:"key"`               // key
	BlockSize int    `yaml:"block_size" json:"block_size"` // 块的大小
}
