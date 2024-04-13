package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/mattn/go-sqlite3"
	_ "github.com/mattn/go-sqlite3"
	"sso/internal/domain/models"
	"sso/internal/storage"
)

type Storage struct {
	db *sql.DB
}

func New(storagePath string) (*Storage, error) {
	const op = "sqlite/New"

	db, err := sql.Open("sqlite3", storagePath)
	if err != nil {
		return nil, fmt.Errorf("%s : %w", op, err)
	}

	return &Storage{db: db}, nil
}

func (s *Storage) SaveUser(ctx context.Context, email string, passHash []byte) (int64, error) {
	const op = "sqlite/SaveUser"

	stmt, err := s.db.Prepare("INSERT INTO users (email, pass_hash) VALUES (?, ?)")
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	res, err := stmt.ExecContext(ctx, email, passHash)
	if err != nil {
		var sqliteErr sqlite3.Error

		if errors.As(err, &sqliteErr) && errors.Is(sqliteErr.ExtendedCode, sqlite3.ErrConstraintUnique) {
			return 0, fmt.Errorf("%s : %w", op, storage.ErrUserExist)
		}

		return 0, fmt.Errorf("%s : %w", op, err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("%s : %w", op, err)
	}

	return id, nil
}

func (s *Storage) User(ctx context.Context, email string) (models.User, error) {
	const op = "sqlite/User"

	stmt, err := s.db.Prepare("SELECT id, email, pass_hash FROM users where email = ?")
	if err != nil {
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}
	var user models.User
	err = stmt.QueryRowContext(ctx, email).Scan(&user.ID, &user.Email, &user.PassHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.User{}, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}

	return user, nil
}

func (s *Storage) IsAdmin(ctx context.Context, userID int64) (bool, error) {
	const op = "sqlite/IsAdmin"

	stmt, err := s.db.Prepare("SELECT is_admin FROM users where id = ?")
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}
	var check bool

	err = stmt.QueryRowContext(ctx, userID).Scan(&check)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}
		return false, fmt.Errorf("%s: %w", op, err)
	}

	return check, nil
}

func (s *Storage) App(ctx context.Context, appId int32) (models.App, error) {
	const op = "sqlite/App"

	stmt, err := s.db.Prepare("SELECT id, name, secret from apps where id = ?")
	if err != nil {
		return models.App{}, fmt.Errorf("%s: %w", op, err)
	}
	var app models.App
	err = stmt.QueryRowContext(ctx, appId).Scan(&app.AppId, &app.Name, &app.Secret)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.App{}, fmt.Errorf("%s: %w", op, storage.ErrAppNotFound)
		}
		return models.App{}, fmt.Errorf("%s: %w", op, err)
	}

	return app, nil
}
