package hex

import "encoding/hex"

type Hex struct {
}

func NewHex() *Hex {
	h := Hex{}
	return &h
}

func (h *Hex) Encode(data []byte) []byte {
	maxEnLen := hex.EncodedLen(len(data)) // 最大编码长度
	dst1 := make([]byte, maxEnLen)
	n := hex.Encode(dst1, data)
	return dst1[:n]
}

func (h *Hex) Decode(data []byte) ([]byte, error) {
	maxDeLen := hex.DecodedLen(len(data))
	dst1 := make([]byte, maxDeLen)
	n, err := hex.Decode(dst1, data)
	return dst1[:n], err
}

func (h *Hex) EncodeString(data string) string {
	return hex.EncodeToString([]byte(data))
}

func (h *Hex) DecodeString(data string) (string, error) {
	decode, err := h.Decode([]byte(data))
	if err != nil {
		return "", err
	}
	return string(decode), err
}
