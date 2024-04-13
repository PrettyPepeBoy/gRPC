package storage

import "errors"

var (
	ErrUserExist    = errors.New("user is already exists")
	ErrUserNotFound = errors.New("user not found")
	ErrAppNotFound  = errors.New("app is not found")
)
