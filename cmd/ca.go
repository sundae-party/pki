/*
Copyright © 2021 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/sundae-party/pki/ca"
)

var dest string
var caCertFileName string
var caKeyFileName string
var cn string
var timeExp int

// caCmd represents the ca command
var caCmd = &cobra.Command{
	Use:   "ca",
	Short: "Create new self signed CA",
	Long:  `Create new self signed CA.`,
	RunE: func(cmd *cobra.Command, args []string) error {

		// Buil CA with given CN
		caSubj := &pkix.Name{
			CommonName: cn,
		}

		// Set the cert validity
		stringTimeExp := fmt.Sprintf("%dh", timeExp)
		yearDuration, err := time.ParseDuration(stringTimeExp)
		if err != nil {
			log.Fatalln(err)
		}

		// Gen new CA
		rootCa := ca.CreateCa(*caSubj, time.Now(), yearDuration)

		// Create ssl folder
		err = os.Mkdir(dest, 0700)
		if err != nil {
			return err
		}

		// Build cert & key dest path
		certPath := fmt.Sprintf("%s/%s", dest, caCertFileName)
		keyPath := fmt.Sprintf("%s/%s", dest, caKeyFileName)

		// Write CA cert files
		err = ioutil.WriteFile(certPath, rootCa.CertPem.Bytes(), 0600)
		if err != nil {
			return err
		}

		// Write CA key files
		err = ioutil.WriteFile(keyPath, rootCa.KeyPem.Bytes(), 0600)
		if err != nil {
			return err
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(caCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	caCmd.Flags().StringVarP(&dest, "dest", "d", "ssl", "Destination where CA cert and key files will be created. (default is ./ssl)")

	caCmd.Flags().StringVar(&cn, "cn", "", "Common Name to add in the CA.")
	caCmd.MarkFlagRequired("cn")

	caCmd.Flags().StringVar(&caCertFileName, "certName", "ca.pem", "CA cert file name. (default is ca.pem)")
	caCmd.Flags().StringVar(&caKeyFileName, "keyName", "ca.key", "CA key file name. (default is ca.key)")
	caCmd.Flags().IntVar(&timeExp, "exp", 87600, "Time when the cert will expire from now. (default is 87600h - 10 years)")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// caCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
