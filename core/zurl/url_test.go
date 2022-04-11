package zurl

import "testing"

func getUrl() *Url {
	return NewUrl()
}

// 测试基本使用
func TestUrl_basic(t *testing.T) {
	u := getUrl()
	urlPath := "https://www.google.com?kw=张大鹏"

	// 编码
	urlEncode := u.Encode(urlPath)
	t.Log(urlEncode)

	// 解码
	urlDecode, err := u.Decode(urlEncode)
	if err != nil {
		t.Error(err)
	}
	t.Log(urlDecode)
}
