package cmd

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/exp/slog"

	"github.com/randa-mu/ssv-dkg/sidecar"
)

var (
	PortFlag          uint
	PublicKeyPathFlag string
	PublicURLFlag     string
	VerboseFlag       bool
	startCmd          = &cobra.Command{
		Use:   "start",
		Short: "Start the DKG sidecar",
		Long:  "Start the DKG sidecar daemon, enabling the creation of validator clusters using a distributed key.",
		Run:   Start,
	}
)

func init() {
	startCmd.PersistentFlags().UintVarP(
		&PortFlag,
		"port",
		"p",
		8080,
		"the public port you wish to run the sidecar server on",
	)
	startCmd.PersistentFlags().StringVarP(
		&PublicKeyPathFlag,
		"ssv-key",
		"s",
		"",
		"the filepath of your SSV node's encrypted key file",
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
	startCmd.PersistentFlags().Uint32VarP(
		&OperatorIDFlag,
		"operator-id",
		"i",
		0,
		"the operator ID you received from the smart contract when registering your SSV node",
	)
}

func Start(_ *cobra.Command, _ []string) {
	if VerboseFlag {
		l := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		}))
		slog.SetDefault(l)
	}

	daemon, err := sidecar.NewDaemon(PortFlag, PublicURLFlag, DirectoryFlag, PublicKeyPathFlag, OperatorIDFlag)
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
