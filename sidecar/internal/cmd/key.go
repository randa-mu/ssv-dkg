package cmd

import (
	"fmt"
	"path"

	"github.com/randa-mu/ssv-dkg/shared"
	"github.com/randa-mu/ssv-dkg/sidecar"
	"github.com/randa-mu/ssv-dkg/sidecar/internal/util"
	"github.com/spf13/cobra"
)

var UrlFlag string
var ValidatorNonceFlag uint32
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
	keySignCmd.PersistentFlags().Uint32VarP(
		&ValidatorNonceFlag,
		"validator-nonce",
		"n",
		0,
		"The validator nonce received when you registered your SSV node with the SSV contract",
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

	err := sidecar.GenerateKey(dir)
	if err != nil {
		shared.Exit(fmt.Sprintf("%v", err))
	}

	fmt.Printf("Created a new keypair at %s\n", path.Join(dir, util.KeySuffix))
}

func signKey(_ *cobra.Command, _ []string) {
	signature, err := sidecar.SignKey(UrlFlag, ValidatorNonceFlag, DirectoryFlag)
	if err != nil {
		shared.Exit(fmt.Sprintf("%v", err))
	}
	fmt.Println(string(signature))
}
