package utils

import (
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"time"

	"github.com/sundae-party/pki/ca"
	"github.com/sundae-party/pki/csr"
)

func CreateCertFromCAFile(caKeyPath string, caCertPath string, cn string, duration time.Duration, sansDns []string, sansIp []net.IP, dest string, certFileName string, keyFileName string) error {

	// Load CA
	caCert, err := LoadCertFromFile(caKeyPath, "", caCertPath)
	if err != nil {
		return err
	}

	// Build new cert subject with CN
	certSubj := &pkix.Name{
		CommonName: cn,
	}

	// Create CSR
	csrSrv := csr.CreateCSR(*certSubj, sansDns, sansIp, time.Now(), duration)
	// Sign CSR with given CA
	cert := ca.Sign(caCert, csrSrv)

	// Create destination folder
	if _, err := os.Stat(dest); os.IsNotExist(err) {
		err := os.Mkdir(dest, 0700)
		if err != nil {
			return err
		}
	}

	// Build cert path and key path
	certPath := fmt.Sprintf("%s/%s", dest, certFileName)
	keyPath := fmt.Sprintf("%s/%s", dest, keyFileName)

	// Write Cert and Key files
	err = ioutil.WriteFile(certPath, cert.CertPem.Bytes(), 0600)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(keyPath, cert.KeyPem.Bytes(), 0600)
	if err != nil {
		return err
	}

	return nil
}
