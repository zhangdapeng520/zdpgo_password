package zdpgo_password

import "testing"

func TestBase64Encode(t *testing.T) {
	data := "https://www.baidu.com?key=张大鹏"
	result := Base64Encode([]byte(data))
	t.Log(result)
}

func TestBase64Decode(t *testing.T) {
	data := "aHR0cHM6Ly93d3cuYmFpZHUuY29tP2tleT3lvKDlpKfpuY8="
	result := Base64Decode(data)
	t.Log(result)
}

func TestBase64URLEncode(t *testing.T) {
	data := "https://www.baidu.com?key=张大鹏"
	result := Base64URLEncode([]byte(data))
	t.Log(result)
}

func TestBase64URLDecode(t *testing.T) {
	data := "aHR0cHM6Ly93d3cuYmFpZHUuY29tP2tleT3lvKDlpKfpuY8="
	result := Base64URLDecode(data)
	t.Log(result)
}
