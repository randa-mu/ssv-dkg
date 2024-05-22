package cmd

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/randa-mu/ssv-dkg/sidecar"
	"github.com/spf13/cobra"
	"golang.org/x/exp/slog"
)

var PortFlag uint
var SsvURLFlag string
var PublicURLFlag string
var VerboseFlag bool
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
		"http://127.0.0.1:8888",
		"the hostname and port of the SSV binary you wish to connect to",
	)
	startCmd.PersistentFlags().StringVarP(
		&PublicURLFlag,
		"public-url",
		"u",
		"",
		"the public endpoint you host your node on",
	)
	startCmd.PersistentFlags().BoolVarP(
		&VerboseFlag,
		"verbose",
		"v",
		false,
		"enables more detailed logging if provided",
	)
}

func Start(_ *cobra.Command, _ []string) {
	if VerboseFlag {
		l := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		}))
		slog.SetDefault(l)
	}

	daemon, err := sidecar.NewDaemon(PortFlag, PublicURLFlag, SsvURLFlag, DirectoryFlag)
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
	if !errors.Is(err, http.ErrServerClosed) {
		slog.Error("error running daemon", "err", err)
		os.Exit(1)
	}
}
