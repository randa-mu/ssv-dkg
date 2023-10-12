package cmd

import (
	"fmt"
	"github.com/randa-mu/ssv-dkg/sidecar/internal"
	"github.com/spf13/cobra"
)

var PortFlag uint
var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the DKG sidecar",
	Long:  "Start the DKG sidecar daemon, enabling the creation of validator clusters using a distributed key.",
	Run: func(cmd *cobra.Command, args []string) {
		if PortFlag == 0 {
			exit("You must provide a port to start the sidecar")
		}
		daemon, err := internal.NewDaemon(PortFlag)
		if err != nil {
			exit(fmt.Sprintf("error starting daemon: %v", err))
		}

		errs := daemon.Start()
		fmt.Println(fmt.Sprintf("SSV sidecar started, serving on port %d", PortFlag))
		for {
			select {
			case err := <-errs:
				exit(fmt.Sprintf("error while running daemon: %v", err))
			default:
			}
		}
	},
}
