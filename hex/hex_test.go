package hex

import "testing"

func getHex() *Hex {
	return NewHex()
}

func TestHex_basic(t *testing.T) {
	data := "abc 123 张大鹏"

	// 编码
	h := getHex()
	encode := h.Encode([]byte(data))
	t.Log(encode)

	// 解码
	decode, err := h.Decode(encode)
	if err != nil {
		t.Error(err)
	}
	t.Log(string(decode))

	// 编码字符串
	encodeString := h.EncodeString(data)
	t.Log(encodeString)

	// 解码字符串
	decodeString, err := h.DecodeString(encodeString)
	if err != nil {
		t.Error(err)
	}
	t.Log(decodeString)
}
