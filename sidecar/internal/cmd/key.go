package cmd

import (
	"encoding/base64"
	"fmt"
	"github.com/randa-mu/ssv-dkg/sidecar/internal/crypto"
	"github.com/randa-mu/ssv-dkg/sidecar/internal/util"
	"github.com/spf13/cobra"
	"os"
	"path"
)

var UrlFlag string
var keyCmd = &cobra.Command{
	Use:   "key",
	Short: "All operations related to keys",
}

func init() {
	keyCmd.AddCommand(keyCreateCmd)
	keyCmd.AddCommand(keySignCmd)
	keySignCmd.PersistentFlags().StringVarP(&UrlFlag, "url", "u", "", "The public URL of your sidecar node, including port and scheme")
}

var keypairName = "keypair.json"
var keyCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Creates an RSA key for this node",
	Run: func(cmd *cobra.Command, args []string) {
		kp, err := crypto.CreateKeypair()
		if err != nil {
			exit(fmt.Sprintf("failed to create keypair: %v", err))
		}

		keyPath := path.Join(DirectoryFlag, keypairName)
		err = util.StoreKeypair(kp, keyPath)
		if err != nil {
			exit(fmt.Sprintf("failed to store keypair: %v", err))
		}

		fmt.Println(fmt.Sprintf("Created a new keypair at %s", keyPath))
	},
}

var keySignCmd = &cobra.Command{
	Use:   "sign",
	Short: "Writes the signed public key and address to stdout",
	Run: func(cmd *cobra.Command, args []string) {
		if UrlFlag == "" {
			exit("You must pass a URL to associate the keypair with")
		}

		keyPath := path.Join(DirectoryFlag, keypairName)
		keypair, err := util.LoadKeypair(keyPath)
		if err != nil {
			exit(fmt.Sprintf("failed to load keypair from %s: %v", keyPath, err))
		}

		signature, err := keypair.Sign(UrlFlag)
		if err != nil {
			exit(fmt.Sprintf("failed to sign address: %v", err))
		}

		fmt.Println(fmt.Sprintf("Address: %s", UrlFlag))
		fmt.Println(fmt.Sprintf("PublicKey: %s", base64.StdEncoding.EncodeToString(keypair.Public)))
		fmt.Println(fmt.Sprintf("Signature: %s", base64.StdEncoding.EncodeToString(signature)))
	},
}

func exit(message string) {
	fmt.Println(message)
	os.Exit(1)
}
