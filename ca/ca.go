package ca

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/sundae-party/pki/types"
)

// CreateCa generate new self signed CA
func CreateCa(subject pkix.Name, start time.Time, duration time.Duration) *types.Cert {

	// Gen CA private key
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}

	// Get CA pivate key in pem format
	caPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})

	// Gen CA certificate template
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(2021),
		Subject:               subject,
		NotBefore:             start,
		NotAfter:              start.Add(duration),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// Create self signed CA certificate from template signed by the CA private key
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		panic(err)
	}

	// Get CA certificate in pem format
	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	caObj := &types.Cert{
		CertPem: caPEM,
		KeyPem:  caPrivKeyPEM,
		Cert:    ca,
		Key:     caPrivKey,
	}

	return caObj
}

// Sign sign CSR with given CA
func Sign(ca *types.Cert, csr *types.Cert) *types.Cert {

	certBytes, err := x509.CreateCertificate(rand.Reader, csr.Cert, ca.Cert, &csr.Key.PublicKey, ca.Key)
	if err != nil {
		panic(err)
	}

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	certPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(csr.Key),
	})

	certObj := &types.Cert{
		CertPem: certPEM,
		KeyPem:  certPrivKeyPEM,
		Cert:    csr.Cert,
		Key:     csr.Key,
	}

	return certObj
}
