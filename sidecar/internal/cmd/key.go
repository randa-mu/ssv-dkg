package cmd

import (
	"fmt"
	"path"

	"github.com/spf13/cobra"

	"github.com/randa-mu/ssv-dkg/shared"
	"github.com/randa-mu/ssv-dkg/sidecar"
	"github.com/randa-mu/ssv-dkg/sidecar/internal/util"
)

var (
	UrlFlag        string
	OperatorIDFlag uint32
	keyCmd         = &cobra.Command{
		Use:   "key",
		Short: "All operations related to keys",
	}
	keyCreateCmd = &cobra.Command{
		Use:   "create",
		Short: "Creates an RSA key for this node",
		Run:   createKey,
	}
	keySignCmd = &cobra.Command{
		Use:   "sign",
		Short: "Writes the signed public key and address to stdout",
		Run:   signKey,
	}
)

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
		&OperatorIDFlag,
		"operator-id",
		"i",
		0,
		"The operatorID you received when registering your SSV node",
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
	if OperatorIDFlag == 0 {
		shared.Exit("`operator-id` must be set and greater than 0")
	}

	signature, err := sidecar.SignKey(UrlFlag, DirectoryFlag, OperatorIDFlag)
	if err != nil {
		shared.Exit(fmt.Sprintf("%v", err))
	}
	fmt.Println(string(signature))
}
