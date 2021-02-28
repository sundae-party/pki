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

// serverCertCmd represents the serverCert command
var serverCertCmd = &cobra.Command{
	Use:   "serverCert",
	Short: "Create new server cert and key",
	Long:  `Create a new certificate and key signed by a given CA. This certificate should be used to the server SSL configuration.`,
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

		// Get sans from flags
		sansDns, err := cmd.Flags().GetStringSlice("sansDns")
		if err != nil {
			return err
		}
		sansIp, err := cmd.Flags().GetIPSlice("sansIp")
		if err != nil {
			return err
		}

		return utils.CreateCertFromCAFile(caKeyPath, caCertPath, cn, duration, sansDns, sansIp, dest, certFileName, keyFileName)
	},
}

func init() {
	rootCmd.AddCommand(serverCertCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// serverCertCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// serverCertCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	// CA key to signe cert
	serverCertCmd.Flags().String("caKey", "", "CA Key path used to sign the new certificate.")
	serverCertCmd.MarkFlagRequired("caKey")

	// CA cert to signe cert
	serverCertCmd.Flags().String("caCert", "", "CA Cert path used to sign the new certificate.")
	serverCertCmd.MarkFlagRequired("caCert")

	// CN
	serverCertCmd.Flags().String("certCn", "", "Common Name to add in the new cert.")
	serverCertCmd.MarkFlagRequired("certCn")

	// Destination
	serverCertCmd.Flags().StringP("dest", "d", "ssl", "Destination where the cert and key files will be created. (default is ./ssl)")

	// Files name
	serverCertCmd.Flags().String("certFileName", "srv.pem", "The cert file name. (default is srv.pem)")
	serverCertCmd.Flags().String("keyFileName", "srv.key", "The key file name. (default is srv.key)")

	// Duration
	serverCertCmd.Flags().Int("exp", 87600, "Time when the cert will expire from now. (default is 87600h - 10 years)")

	// SANS DSN
	serverCertCmd.Flags().StringSlice("sansDns", []string{}, "Additional dns in SANS")

	// SANS IP
	serverCertCmd.Flags().IPSlice("sansIp", []net.IP{}, "Additional IPs in SANS")

}
