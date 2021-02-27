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
	"log"

	"github.com/spf13/cobra"

	"github.com/sundae-party/pki/utils"
)

// readCmd represents the read command
var readCmd = &cobra.Command{
	Use:   "read",
	Short: "Show info about a cert",
	Long:  ``,
	RunE: func(cmd *cobra.Command, args []string) error {

		// Build cert path and key path
		certFilePath, err := cmd.Flags().GetString("cert")
		if err != nil {
			return err
		}
		keyFilePath, err := cmd.Flags().GetString("key")
		if err != nil {
			return err
		}
		cert, err := utils.LoadCertFromFile(keyFilePath, "", certFilePath)
		if err != nil {
			return err
		}

		log.Printf("DNS Names : %s \n", cert.Cert.DNSNames)
		log.Printf("Ip : %s", cert.Cert.IPAddresses)
		log.Printf("Is CA : %t \n", cert.Cert.IsCA)
		log.Printf("Not Before : %s", cert.Cert.NotBefore)
		log.Printf("NotAfter : %s", cert.Cert.NotAfter)
		log.Printf("Subject : %s", cert.Cert.Subject)

		return nil
	},
}

func init() {
	rootCmd.AddCommand(readCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// readCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// readCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	readCmd.Flags().StringP("key", "k", "", "Key path.")
	readCmd.MarkFlagRequired("key")

	readCmd.Flags().StringP("cert", "c", "", "Cert path.")
	readCmd.MarkFlagRequired("cert")
}
