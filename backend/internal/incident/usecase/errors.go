package usecase

import "errors"

// errsIs exists so mutate.go can shadow the package name `errs` for the
// domain error package without losing errors.Is.
func errsIs(err, target error) bool { return errors.Is(err, target) }
