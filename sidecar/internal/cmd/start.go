package cmd

import (
	"github.com/randa-mu/ssv-dkg/sidecar"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"path"
)

var PortFlag uint
var SsvURLFlag string
var PublicURLFlag string
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
	startCmd.PersistentFlags().StringVarP(
		&PublicURLFlag,
		"public-url",
		"u",
		"",
		"the public endpoint you host your node on",
	)
}

func Start(_ *cobra.Command, _ []string) {
	daemon, err := sidecar.NewDaemon(PortFlag, PublicURLFlag, SsvURLFlag, path.Join(DirectoryFlag, KeypairFilename))
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
