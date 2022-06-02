package goEncrypt

import "errors"

var (
	ErrCipherKey           = errors.New("The secret key is wrong and cannot be decrypted. Please check")
	ErrKeyLengthSixteen    = errors.New("a sixteen or twenty-four or thirty-two length secret key is required")
	ErrKeyLengtheEight     = errors.New("a eight-length secret key is required")
	ErrKeyLengthTwentyFour = errors.New("a twenty-four-length secret key is required")
	ErrPaddingSize         = errors.New("padding size error please check the secret key or iv")
	ErrIvAes               = errors.New("a sixteen-length ivaes is required")
	ErrIvDes               = errors.New("a eight-length ivdes key is required")
)

const (
	ivaes = "wumansgy12345678"
	ivdes = "wumansgy"

	privateFileName = "private.pem"
	publicFileName  = "public.pem"

	eccPrivateFileName = "eccprivate.pem"
	eccPublishFileName = "eccpublic.pem"

	privateKeyPrefix = " ZDPGO_PASSWORD RSA PRIVATE KEY "
	publicKeyPrefix  = " ZDPGO_PASSWORD  RSA PUBLIC KEY "

	eccPrivateKeyPrefix = " ZDPGO_PASSWORD ECC PRIVATE KEY "
	eccPublicKeyPrefix  = " ZDPGO_PASSWORD ECC PUBLIC KEY "
)
