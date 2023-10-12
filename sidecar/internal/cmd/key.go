package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/randa-mu/ssv-dkg/shared"
	"github.com/randa-mu/ssv-dkg/shared/crypto"
	"github.com/randa-mu/ssv-dkg/sidecar/internal/util"
	"github.com/spf13/cobra"
	"path"
)

var UrlFlag string
var keyCmd = &cobra.Command{
	Use:   "key",
	Short: "All operations related to keys",
}

var keypairName = "keypair.json"
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

	kp, err := crypto.CreateKeypair()
	if err != nil {
		shared.Exit(fmt.Sprintf("failed to create keypair: %v", err))
	}

	keyPath := path.Join(dir, keypairName)
	err = util.StoreKeypair(kp, keyPath)
	if err != nil {
		shared.Exit(fmt.Sprintf("failed to store keypair: %v", err))
	}

	fmt.Println(fmt.Sprintf("Created a new keypair at %s", keyPath))
}

func signKey(_ *cobra.Command, _ []string) {
	if UrlFlag == "" {
		shared.Exit("You must pass a URL to associate the keypair with")
	}

	keyPath := path.Join(DirectoryFlag, keypairName)
	keypair, err := util.LoadKeypair(keyPath)
	if err != nil {
		shared.Exit(fmt.Sprintf("failed to load keypair from %s: %v", keyPath, err))
	}

	identity, err := keypair.SelfSign(UrlFlag)
	if err != nil {
		shared.Exit(fmt.Sprintf("failed to sign address: %v", err))
	}

	bytes, err := json.Marshal(identity)
	if err != nil {
		shared.Exit(fmt.Sprintf("failed to marshal json for identity: %v", err))
	}
	fmt.Println(string(bytes))
}
