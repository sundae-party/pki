package main

import (
	"crypto/x509/pkix"
	"io/ioutil"
	"log"
	"net"
	"os"
	"time"

	"github.com/sundae-party/pki/ca"
	"github.com/sundae-party/pki/csr"
)

func main() {

	caSubj := &pkix.Name{
		CommonName: "sundae-ca",
	}

	srvCertSubj := &pkix.Name{
		CommonName: "sundae-apiserver",
	}

	cliWebCertSubj := &pkix.Name{
		CommonName: "user:user01",
	}

	grpcWebCertSubj := &pkix.Name{
		CommonName: "integration:integration01",
	}

	// Duration of one year
	yearDuration, err := time.ParseDuration("8760h")
	if err != nil {
		log.Fatalln(err)
	}

	// Gen root CA
	rootCa := ca.CreateCa(*caSubj, time.Now(), yearDuration)

	// Gen server csr
	srvCsr := csr.CreateCSR(*srvCertSubj, []string{"sundae.com", "auth.sundae.com", "localhost"}, []net.IP{net.IPv4(127, 0, 0, 1), net.IPv4(192, 168, 1, 61)}, time.Now(), yearDuration)
	srvCert := ca.Sign(rootCa, srvCsr)

	// Gen web cli csr
	webCsr := csr.CreateCSR(*cliWebCertSubj, []string{}, []net.IP{}, time.Now(), yearDuration)
	webCert := ca.Sign(rootCa, webCsr)

	// Gen gRPC cli csr
	gRPCCsr := csr.CreateCSR(*grpcWebCertSubj, []string{}, []net.IP{}, time.Now(), yearDuration)
	gRPCCert := ca.Sign(rootCa, gRPCCsr)

	os.Mkdir("ssl", 0700)

	// Write CA files
	err = ioutil.WriteFile("ssl/ca.pem", rootCa.CertPem.Bytes(), 0600)
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile("ssl/ca.key", rootCa.KeyPem.Bytes(), 0600)
	if err != nil {
		log.Fatal(err)
	}

	// Write server certs files
	err = ioutil.WriteFile("ssl/sundae-apiserver.pem", srvCert.CertPem.Bytes(), 0600)
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile("ssl/sundae-apiserver.key", srvCert.KeyPem.Bytes(), 0600)
	if err != nil {
		log.Fatal(err)
	}

	// Write web client certs files
	err = ioutil.WriteFile("ssl/user01.pem", webCert.CertPem.Bytes(), 0600)
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile("ssl/user01.key", webCert.KeyPem.Bytes(), 0600)
	if err != nil {
		log.Fatal(err)
	}

	// Write gRPC client certs files
	err = ioutil.WriteFile("ssl/integration01.pem", gRPCCert.CertPem.Bytes(), 0600)
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile("ssl/integration01.key", gRPCCert.KeyPem.Bytes(), 0600)
	if err != nil {
		log.Fatal(err)
	}
}
