package zdpgo_password

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"time"
)

// 创建SSL证书
func SSLCreate() {
	// 最大值
	max := new(big.Int).Lsh(big.NewInt(1), 128)

	// 创建一个非常大的随机整数
	serialNumber, _ := rand.Int(rand.Reader, max)

	// 标题
	subject := pkix.Name{
		Organization:       []string{"zhangdapeng"},   // 作者
		OrganizationalUnit: []string{"golang"},        // 单位
		CommonName:         "zhangdapeng golang chat", // 通用名
	}

	// 配置
	template := x509.Certificate{
		SerialNumber: serialNumber,                                                 // 唯一标识
		Subject:      subject,                                                      // 主题
		NotBefore:    time.Now(),                                                   // 开始时间
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),                         // 过期时间：365天
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature, // 用途：服务器身份验证
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")}, // 使用地址：本机IP
	}

	// 生成RSA私钥
	pk, _ := rsa.GenerateKey(rand.Reader, 2048)

	// 将证书保存到cert.pem
	derBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &pk.PublicKey, pk)
	certOut, _ := os.Create("cert.pem")
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	// 将私钥保存到key.pem
	keyOut, _ := os.Create("key.pem")
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(pk)})
	keyOut.Close()
}
