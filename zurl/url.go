package zurl

import (
	"net/url"
)

type Url struct {
}

func NewUrl() *Url {
	u := Url{}
	return &u
}

// Encode URL编码
func (u *Url) Encode(urlPath string) string {
	encodeUrl := url.QueryEscape(urlPath)
	return encodeUrl
}

// Decode URL解码
func (u *Url) Decode(urlPath string) (string, error) {
	decodeUrl, err := url.QueryUnescape(urlPath)
	return decodeUrl, err
}
