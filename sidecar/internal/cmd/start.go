package cmd

import (
	"fmt"
	"github.com/randa-mu/ssv-dkg/shared"
	"github.com/randa-mu/ssv-dkg/sidecar/internal"
	"github.com/spf13/cobra"
)

var PortFlag uint
var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the DKG sidecar",
	Long:  "Start the DKG sidecar daemon, enabling the creation of validator clusters using a distributed key.",
	Run:   Start,
}

func init() {
	startCmd.PersistentFlags().UintVarP(
		&PortFlag,
		"port",
		"p",
		8080,
		"the public port you wish to run the sidecar server on",
	)
}

func Start(_ *cobra.Command, _ []string) {
	if PortFlag == 0 {
		shared.Exit("You must provide a port to start the sidecar")
	}
	daemon, err := internal.NewDaemon(PortFlag, DirectoryFlag)
	if err != nil {
		shared.Exit(fmt.Sprintf("error starting daemon: %v", err))
	}

	errs := daemon.Start()
	fmt.Println(fmt.Sprintf("SSV sidecar started, serving on port %d", PortFlag))
	for {
		select {
		case err := <-errs:
			shared.Exit(fmt.Sprintf("error while running daemon: %v", err))
		default:
		}
	}
}
