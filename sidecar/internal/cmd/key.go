package cmd

import (
	"fmt"
	"github.com/randa-mu/ssv-dkg/shared"
	"github.com/randa-mu/ssv-dkg/sidecar"
	"github.com/spf13/cobra"
	"path"
)

var UrlFlag string
var keyCmd = &cobra.Command{
	Use:   "key",
	Short: "All operations related to keys",
}

var keyCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Creates an RSA key for this node",
	Run:   createKey,
}

var keySignCmd = &cobra.Command{
	Use:   "sign",
	Short: "Writes the signed public key and address to stdout",
	Run:   signKey,
}

func init() {
	keyCmd.AddCommand(keyCreateCmd, keySignCmd)
	keySignCmd.PersistentFlags().StringVarP(
		&UrlFlag,
		"url",
		"u",
		"",
		"The public URL of your sidecar node, including port and scheme",
	)
}

var KeypairFilename = "keypair.json"

func createKey(_ *cobra.Command, args []string) {
	var dir string
	if len(args) > 1 {
		shared.Exit(fmt.Sprintf("too many args - expected 1, got %d", len(args)))
	}

	if len(args) == 1 {
		dir = args[0]
	} else {
		dir = DirectoryFlag
	}

	keyPath := path.Join(dir, KeypairFilename)
	err := sidecar.GenerateKey(keyPath)
	if err != nil {
		shared.Exit(fmt.Sprintf("%v", err))
	}

	fmt.Printf("Created a new keypair at %s\n", keyPath)
}

func signKey(_ *cobra.Command, _ []string) {
	keyPath := path.Join(DirectoryFlag, KeypairFilename)
	signature, err := sidecar.SignKey(UrlFlag, keyPath)
	if err != nil {
		shared.Exit(fmt.Sprintf("%v", err))
	}
	fmt.Println(string(signature))
}
