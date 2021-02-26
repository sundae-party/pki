package utils

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"

	"github.com/sundae-party/pki/types"
)

func LoadCertFromFile(keyPath string, rsaPrivateKeyPassword string, certPath string) (certObj *types.Cert, err error) {

	// open cert
	certBytes, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	certBlock, _ := pem.Decode(certBytes)
	cert, err := x509.ParseCertificate(certBlock.Bytes)

	// Gen cert pem
	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, certBlock)

	// Get RSA key from file
	key, certPrivKeyPEM, err := loadRsa(keyPath, rsaPrivateKeyPassword)
	if err != nil {
		return nil, err
	}

	certObj = &types.Cert{
		CertPem: certPEM,
		KeyPem:  certPrivKeyPEM,
		Cert:    cert,
		Key:     key,
	}

	return certObj, nil
}

func loadRsa(keyPath string, rsaPrivateKeyPassword string) (*rsa.PrivateKey, *bytes.Buffer, error) {
	// open key file
	keyBytes, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}

	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock.Type != "RSA PRIVATE KEY" {
		return nil, nil, errors.New("RSA private key is of the wrong type")
	}

	var privPemBytes []byte
	if rsaPrivateKeyPassword != "" {
		privPemBytes, err = x509.DecryptPEMBlock(keyBlock, []byte(rsaPrivateKeyPassword))
		if err != nil {
			return nil, nil, err
		}
	} else {
		privPemBytes = keyBlock.Bytes
	}

	key, err := x509.ParsePKCS1PrivateKey(privPemBytes)
	if err != nil {
		return nil, nil, err
	}

	pem := bytes.NewBuffer(privPemBytes)
	return key, pem, nil
}
