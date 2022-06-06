package zdpgo_password

import "testing"

/*
@Time : 2022/6/1 20:28
@Author : 张大鹏
@File : ecc_test.go
@Software: Goland2021.3.1
@Description:
*/

func TestEcc_EncryptDecrypt(t *testing.T) {
	p := New(&Config{})
	e := p.GetEcc()

	s := "abc"
	data := []byte(s)

	// 加密数据
	encryptData, err := e.Encrypt(data)
	if err != nil {
		panic(err)
	}

	// 解密数据
	decrypt, err := e.Decrypt(encryptData)
	if err != nil {
		panic(err)
	}

	// 比较结果
	if s != string(decrypt) {
		panic("加密前的数据和解密后的数据不一致")
	}
}

// 测试通过私钥解密数据
func TestEcc_EncryptDecryptByKey(t *testing.T) {
	p := New(&Config{})
	e := p.GetEcc()

	s := "abc"
	data := []byte(s)
	privateKey := `-----BEGIN  ZDPGO_PASSWORD ECC PRIVATE KEY -----
MHcCAQEEIKyfOnD7NdXudekftRtH2mBuOPf/UTzJ1Ulo2Hiu22XvoAoGCCqGSM49
AwEHoUQDQgAEXClGdjDvOFSHJzs2LtSfGcVzP58cc9ybrYOo7t6bs818HMybbahM
Qylb+qB4aTtHV0JPqZAr8MChRmvze7nNFw==
-----END  ZDPGO_PASSWORD ECC PRIVATE KEY -----
`
	publicKey := `-----BEGIN  ZDPGO_PASSWORD ECC PUBLIC KEY -----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXClGdjDvOFSHJzs2LtSfGcVzP58c
c9ybrYOo7t6bs818HMybbahMQylb+qB4aTtHV0JPqZAr8MChRmvze7nNFw==
-----END  ZDPGO_PASSWORD ECC PUBLIC KEY -----
`

	// 加密数据
	encryptData, err := e.EncryptByPublicKey(data, []byte(publicKey))
	if err != nil {
		panic(err)
	}

	// 解密数据
	decrypt, err := e.DecryptByPrivateKey(encryptData, []byte(privateKey))
	if err != nil {
		panic(err)
	}

	// 比较结果
	if s != string(decrypt) {
		panic("加密前的数据和解密后的数据不一致")
	}
}

// 测试加密和解密字符串
func TestEcc_EncryptStringDecryptString(t *testing.T) {
	p := New(&Config{})
	e := p.GetEcc()

	s := "abc"

	// 加密数据
	encryptString, err := e.EncryptString(s)
	if err != nil {
		panic(err)
	}

	// 解密数据
	decryptString, err := e.DecryptString(encryptString)
	if err != nil {
		panic(err)
	}

	// 比较结果
	if s != decryptString {
		panic("加密前的数据和解密后的数据不一致")
	}
}

// 测试签名和校验
func TestEcc_SignVerify(t *testing.T) {
	p := New(&Config{})
	e := p.GetEcc()

	s := "abc"
	data := []byte(s)

	// 数据签名
	signData, err := e.Sign(data)
	if err != nil {
		panic(err)
	}

	// 校验数据
	flag := e.Verify(data, signData)
	if !flag {
		panic("校验结果错误")
	}
}
