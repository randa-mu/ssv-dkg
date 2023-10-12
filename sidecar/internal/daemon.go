package internal

import (
	"errors"
	"fmt"
	"github.com/go-chi/chi/v5"
	"net/http"
)

type Daemon struct {
	port   uint
	router chi.Router
}

func NewDaemon(port uint) (Daemon, error) {
	if port == 0 {
		return Daemon{}, errors.New("you must provide a port")
	}
	router := chi.NewMux()
	router.Get("/health", func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
	})

	return Daemon{
		port:   port,
		router: router,
	}, nil
}

func (d Daemon) Start() chan error {
	errs := make(chan error, 1)
	go func() {
		err := http.ListenAndServe(fmt.Sprintf(":%d", d.port), d.router)
		errs <- err
	}()
	return errs
}
