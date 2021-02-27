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

// caCmd represents the ca command
var caCmd = &cobra.Command{
	Use:   "ca",
	Short: "Create new self signed CA",
	Long:  `Create new self signed CA.`,
	RunE: func(cmd *cobra.Command, args []string) error {

		cn, err := cmd.Flags().GetString("dest")
		if err != nil {
			return err
		}

		// Buil CA with given CN
		caSubj := &pkix.Name{
			CommonName: cn,
		}

		timeExp, err := cmd.Flags().GetInt("exp")
		if err != nil {
			return err
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
		dest, err := cmd.Flags().GetString("dest")
		if err != nil {
			return err
		}

		err = os.Mkdir(dest, 0700)
		if err != nil {
			return err
		}

		// Build cert & key dest path
		certFileName, err := cmd.Flags().GetString("certName")
		if err != nil {
			return err
		}
		keyFileName, err := cmd.Flags().GetString("keyName")
		if err != nil {
			return err
		}
		certPath := fmt.Sprintf("%s/%s", dest, certFileName)
		keyPath := fmt.Sprintf("%s/%s", dest, keyFileName)

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
	caCmd.Flags().StringP("dest", "d", "ssl", "Destination where CA cert and key files will be created. (default is ./ssl)")

	caCmd.Flags().String("cn", "", "Common Name to add in the CA.")
	caCmd.MarkFlagRequired("cn")

	caCmd.Flags().String("certName", "ca.pem", "CA cert file name. (default is ca.pem)")
	caCmd.Flags().String("keyName", "ca.key", "CA key file name. (default is ca.key)")
	caCmd.Flags().Int("exp", 87600, "Time when the cert will expire from now. (default is 87600h - 10 years)")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// caCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
