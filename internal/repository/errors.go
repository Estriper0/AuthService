package repository

import "errors"

var (
	ErrUserExists   = errors.New("user exitst")
	ErrUserNotFound = errors.New("user not found")
	ErrAppNotFound  = errors.New("app not found")
)
