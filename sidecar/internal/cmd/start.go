package cmd

import (
	"github.com/randa-mu/ssv-dkg/sidecar/internal"
	"github.com/spf13/cobra"
	"log"
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
		log.Fatalln("You must provide a port to start the sidecar")
	}
	daemon, err := internal.NewDaemon(PortFlag, DirectoryFlag)
	if err != nil {
		log.Fatalf("error starting daemon: %v\n", err)
	}

	errs := daemon.Start()
	log.Printf("SSV sidecar started, serving on port %d\n", PortFlag)
	for {
		err := <-errs
		log.Fatalf("error while running daemon: %v\n", err)
	}
}
