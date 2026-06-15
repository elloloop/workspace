package service

import (
	"errors"
	"strings"
)

func isNotFound(err error) bool      { return errors.Is(err, ErrNotFound) }
func isAlreadyExists(err error) bool { return errors.Is(err, ErrAlreadyExists) }

func trimName(s string) string { return strings.TrimSpace(s) }
