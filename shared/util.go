package shared

import (
	"fmt"
	"sync"
)

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

type SafeList[T any] struct {
	lock     sync.RWMutex
	delegate []T
}

func (s *SafeList[T]) Append(value T) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.delegate = append(s.delegate, value)
}

func (s *SafeList[T]) Get() []T {
	s.lock.RLock()
	defer s.lock.RUnlock()
	out := make([]T, len(s.delegate))
	copy(out, s.delegate)
	return out
}

func Clone[T any](a []T) []T {
	b := make([]T, len(a))
	copy(b, a)
	return b
}
