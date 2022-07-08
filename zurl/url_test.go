package zurl

import (
	"net/url"
	"testing"
)

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

	// 特殊URL
	url1 := "http://10.1.3.12:8888/file=?%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66%%36%35%%37%34%%36%33%%32%66%%37%30%%36%31%%37%33%%37%33%%37%37%%36%34"
	urlDecode, err = url.QueryUnescape(url1)
	if err != nil {
		t.Error(err)
	}
	t.Log(urlDecode)
}
