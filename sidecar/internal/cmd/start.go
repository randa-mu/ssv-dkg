package cmd

import (
	"github.com/randa-mu/ssv-dkg/sidecar"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"path"
)

var PortFlag uint
var SsvURLFlag string
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
	startCmd.PersistentFlags().StringVarP(
		&SsvURLFlag,
		"ssv-url",
		"s",
		"http://localhost:8888",
		"the hostname and port of the SSV binary you wish to connect to",
	)
}

func Start(_ *cobra.Command, _ []string) {
	if PortFlag == 0 {
		log.Fatal().Msg("You must provide a port to start the sidecar")
	}
	daemon, err := sidecar.NewDaemon(PortFlag, SsvURLFlag, path.Join(DirectoryFlag, KeypairFilename))
	if err != nil {
		log.Fatal().Err(err).Msg("error starting daemon")
	}

	errs := daemon.Start()
	log.Info().Msgf("SSV sidecar started, serving on port %d", PortFlag)
	for {
		err := <-errs
		log.Fatal().Err(err).Msg("error running daemon")
	}
}
