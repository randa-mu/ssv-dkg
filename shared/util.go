package shared

import (
	"fmt"
	"os"
)

// Exit is a helper function for bombing out of the process in CLI commands
func Exit(message string) {
	_, _ = fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}

// Uniq takes an array and returns a new array without duplicates
func Uniq[T comparable](input []T) []T {
	out := make([]T, 0)
	set := make(map[T]bool)

	for _, item := range input {
		if _, found := set[item]; !found {
			set[item] = true
			out = append(out, item)
		}
	}

	return out
}

type QuietLogger struct {
	Quiet bool
}

func (q QuietLogger) MaybeLog(message string) {
	if !q.Quiet {
		fmt.Println(message)
	}
}

func (q QuietLogger) Log(message string) {
	fmt.Println(message)
}
