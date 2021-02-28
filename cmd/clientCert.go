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
	"fmt"
	"log"
	"net"
	"time"

	"github.com/spf13/cobra"
	"github.com/sundae-party/pki/utils"
)

// clientCertCmd represents the clientCert command
var clientCertCmd = &cobra.Command{
	Use:   "clientCert",
	Short: "Manage client certificate",
	Long:  `Create a new client cert signed by a CA in order to be used with the mTLS authentication`,
	RunE: func(cmd *cobra.Command, args []string) error {

		// Get CA info from flags
		caKeyPath, err := cmd.Flags().GetString("caKey")
		if err != nil {
			return err
		}
		caCertPath, err := cmd.Flags().GetString("caCert")
		if err != nil {
			return err
		}

		// Get CN from flag
		cn, err := cmd.Flags().GetString("certCn")
		if err != nil {
			return err
		}

		// Build the cert validity from flags
		durationString, err := cmd.Flags().GetInt("exp")
		if err != nil {
			return err
		}
		formatedDurationString := fmt.Sprintf("%dh", durationString)
		duration, err := time.ParseDuration(formatedDurationString)
		if err != nil {
			log.Fatalln(err)
		}

		// Get destination folder
		dest, err := cmd.Flags().GetString("dest")
		if err != nil {
			return err
		}

		// Get files name from flags
		certFileName, err := cmd.Flags().GetString("certFileName")
		if err != nil {
			return err
		}
		keyFileName, err := cmd.Flags().GetString("keyFileName")
		if err != nil {
			return err
		}

		return utils.CreateCertFromCAFile(caKeyPath, caCertPath, cn, duration, []string{}, []net.IP{}, dest, certFileName, keyFileName)
	},
}

func init() {
	rootCmd.AddCommand(clientCertCmd)

	// CA key to signe cert
	clientCertCmd.Flags().String("caKey", "", "CA Key path used to sign the new certificate.")
	clientCertCmd.MarkFlagRequired("caKey")

	// CA cert to signe cert
	clientCertCmd.Flags().String("caCert", "", "CA Cert path used to sign the new certificate.")
	clientCertCmd.MarkFlagRequired("caCert")

	// CN
	clientCertCmd.Flags().String("certCn", "", "Common Name to add in the new cert.")
	clientCertCmd.MarkFlagRequired("certCn")

	// Destination
	clientCertCmd.Flags().StringP("dest", "d", "ssl", "Destination where the cert and key files will be created. (default is ./ssl)")

	// Files name
	clientCertCmd.Flags().String("certFileName", "client.pem", "The cert file name. (default is srv.pem)")
	clientCertCmd.Flags().String("keyFileName", "client.key", "The key file name. (default is srv.key)")

	// Duration
	clientCertCmd.Flags().Int("exp", 87600, "Time when the cert will expire from now. (default is 87600h - 10 years)")
}
