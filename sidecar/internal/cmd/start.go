package cmd

import (
	"fmt"
	"github.com/randa-mu/ssv-dkg/sidecar"
	"github.com/spf13/cobra"
	"golang.org/x/exp/slog"
	"os"
	"os/signal"
	"path"
	"syscall"
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
		slog.Error("error starting daemon", "err", err)
		os.Exit(1)
	}

	errs := daemon.Start()

	// kill the server gracefully on
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		daemon.Stop()
	}()

	slog.Info(fmt.Sprintf("SSV sidecar started, serving on port %d", PortFlag))
	err = <-errs
	slog.Error("error running daemon", "err", err)
	os.Exit(1)
}
