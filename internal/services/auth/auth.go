package auth

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
	"sso/internal/domain/models"
	"sso/internal/lib/jwt"
	"sso/internal/lib/logger/sl"
	"sso/internal/storage"
	"time"
)

type Auth struct {
	log          *slog.Logger
	userSaver    UserSaver
	userProvider UserProvider
	appProvider  AppProvider
	tokenTTL     time.Duration
}

type UserSaver interface {
	SaveUser(ctx context.Context, email string, passHash []byte) (uid int64, err error)
}

type UserProvider interface {
	User(ctx context.Context, email string) (models.User, error)
	IsAdmin(ctx context.Context, userID int64) (bool, error)
}

type AppProvider interface {
	App(ctx context.Context, appId int32) (models.App, error)
}

var ErrInvalidCredentials = errors.New("invalid credentials")

func New(log *slog.Logger, userSaver UserSaver, userProvider UserProvider, appProvider AppProvider, tokenTTL time.Duration) *Auth {
	return &Auth{
		log:          log,
		userSaver:    userSaver,
		userProvider: userProvider,
		appProvider:  appProvider,
		tokenTTL:     tokenTTL,
	}
}

func (a *Auth) RegisterNewUser(ctx context.Context, email string, pass string) (int64, error) {
	const op = "auth/RegisterNewUser"

	log := a.log.With(
		slog.String("op", op),
		slog.String("email", email),
	)

	log.Info("registering new user")
	passHash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to register new user", sl.Err(err))
		return 0, fmt.Errorf("%s : %w", op, err)
	}
	id, err := a.userSaver.SaveUser(ctx, email, passHash)
	if err != nil {
		if errors.Is(err, storage.ErrUserExist) {
			a.log.Warn("user is already exist", sl.Err(err))
			return 0, fmt.Errorf("%s : %w", op, storage.ErrUserExist)
		}
		log.Error("failed to save new user", sl.Err(err))
		return 0, fmt.Errorf("%s : %w", op, err)
	}

	log.Info("user registred")
	return id, nil
}

func (a *Auth) Login(ctx context.Context, email string, password string, appId int32) (string, error) {
	const op = "auth/Login"

	log := a.log.With(
		slog.String("op", op),
		slog.String("email", email),
	)

	log.Info("starting login user")

	user, err := a.userProvider.User(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			a.log.Warn("user is not found", sl.Err(err))
			return "", fmt.Errorf("%s : %w", op, ErrInvalidCredentials)
		}

		a.log.Error("failed to get user", sl.Err(err))
		return "", fmt.Errorf("%s : %w", op, err)
	}

	if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		a.log.Info("invalid credentials")
		return "", fmt.Errorf("%s : %w", op, ErrInvalidCredentials)
	}

	app, err := a.appProvider.App(ctx, appId)
	if err != nil {
		if errors.Is(err, storage.ErrAppNotFound) {
			a.log.Warn("app is not found", sl.Err(err))
			return "", fmt.Errorf("%s : %w", op, storage.ErrAppNotFound)
		}
		return "", fmt.Errorf("%s : %w", op, err)
	}

	log.Info("user logged successfully")

	token, err := jwt.GenerateToken(user, app, a.tokenTTL)
	if err != nil {
		a.log.Error("failed to generate token")
		return "", fmt.Errorf("%s : %w", op, err)
	}
	return token, nil
}

func (a *Auth) IsAdmin(ctx context.Context, userID int64) (bool, error) {
	const op = "auth/IsAdmin"

	log := a.log.With(
		slog.String("op", op),
		slog.Int64("user_id", userID),
	)

	log.Info("checking if user is admin")

	isAdmin, err := a.userProvider.IsAdmin(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Warn("user not found", sl.Err(err))
			return false, fmt.Errorf("%s, %w", op, storage.ErrUserNotFound)
		}
		return false, fmt.Errorf("%s : %w", op, err)
	}

	log.Info("check if user is admin", slog.Bool("isAdmin", isAdmin))
	return isAdmin, nil
}
