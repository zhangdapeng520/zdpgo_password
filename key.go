package zdpgo_password

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
)

/*
@Time : 2022/6/1 16:17
@Author : 张大鹏
@File : key.go
@Software: Goland2021.3.1
@Description:
*/

const (
	eccPrivateKeyPrefix = " WUMAN ECC PRIVATE KEY "
	eccPublicKeyPrefix  = " WUMAN ECC PUBLIC KEY "
	eccPrivateFileName  = "eccprivate.pem"
	eccPublishFileName  = "eccpublic.pem"
)

func GetEccKey() error {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	x509PrivateKey, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return err
	}

	block := pem.Block{
		Type:  eccPrivateKeyPrefix,
		Bytes: x509PrivateKey,
	}
	file, err := os.Create(eccPrivateFileName)
	if err != nil {
		return err
	}
	defer file.Close()
	if err = pem.Encode(file, &block); err != nil {
		return err
	}

	x509PublicKey, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return err
	}
	publicBlock := pem.Block{
		Type:  eccPublicKeyPrefix,
		Bytes: x509PublicKey,
	}
	publicFile, err := os.Create(eccPublishFileName)
	if err != nil {
		return err
	}
	defer publicFile.Close()
	if err = pem.Encode(publicFile, &publicBlock); err != nil {
		return err
	}
	return nil
}
