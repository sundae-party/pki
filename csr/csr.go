package csr

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"

	"github.com/sundae-party/pki/types"
)

// CreateCSR generate new CSR certificate and attached private key
func CreateCSR(subject pkix.Name, sansDns []string, sansIP []net.IP, start time.Time, duration time.Duration) *types.Cert {

	// Gen new RSA key
	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}

	// Gen CSR template
	csr := &x509.Certificate{
		SerialNumber: big.NewInt(2021),
		Subject:      subject,
		DNSNames:     sansDns,
		IPAddresses:  sansIP,
		NotBefore:    start,
		NotAfter:     start.Add(duration),
		SubjectKeyId: []byte{1, 2, 3, 4, 5, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certObj := &types.Cert{
		Cert: csr,
		Key:  certPrivKey,
	}
	return certObj
}
