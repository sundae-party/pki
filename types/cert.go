package types

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
)

// Cert certificate object with cert and key in pem and byte format
type Cert struct {
	CertPem *bytes.Buffer
	KeyPem  *bytes.Buffer
	Cert    *x509.Certificate
	Key     *rsa.PrivateKey
}
