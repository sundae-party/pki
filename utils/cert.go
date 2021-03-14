package utils

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"time"

	"google.golang.org/grpc/credentials"

	"github.com/sundae-party/pki/ca"
	"github.com/sundae-party/pki/csr"
)

//CreateCertFromCAFile create a new certificate and private key.
// That can be used at the server side for TLS server configuration and
// at the client side for the mTLS authentication
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

// BuildServerTlsConf create a tlsConfig object of type *tls.Config configured to be used in the server side.
// If one or more CA certificates are provided through CAPaths,
// mTLS configuration will be enabled and this certificates will be used to validate the client certificates.
func BuildServerTlsConf(CAPaths []string, certPath string, keyPath string) (tlsConfig *tls.Config, err error) {

	// SSL server configuration
	serverCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}

	// mTLS configuration
	if len(CAPaths) > 0 {
		caCertPool := x509.NewCertPool()

		// Create a CA certificate pool with all CAs used to sign client certificates for the mTLS.
		for _, caPath := range CAPaths {
			caCert, err := ioutil.ReadFile(caPath)
			if err != nil {
				log.Fatal(err)
			}
			caCertPool.AppendCertsFromPEM(caCert)
		}

		// Create the server TLS Config with the CA pool and enable Client certificate validation.
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		tlsConfig.ClientCAs = caCertPool
	}

	return tlsConfig, nil
}

// LoadKeyPair create a tlsConfig object of type credentials.TransportCredentials configured to be used in the gRPC client side with mTLS enabled.
func LoadKeyPair(certPath string, keyPath string, caPath string) (clientTLSConfig credentials.TransportCredentials, err error) {

	// Load client cert & key
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	// Load CA
	ca, err := ioutil.ReadFile(caPath)
	if err != nil {
		return nil, err
	}

	capool := x509.NewCertPool()
	if !capool.AppendCertsFromPEM(ca) {
		return nil, errors.New("Cann't add ca")
	}

	// Build TLS config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		RootCAs:      capool,
	}

	return credentials.NewTLS(tlsConfig), nil
}
