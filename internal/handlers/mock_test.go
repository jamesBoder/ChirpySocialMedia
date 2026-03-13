package handlers

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jamesboder/ChirpySocialMedia/internal/auth"
	"github.com/jamesboder/ChirpySocialMedia/internal/database"
)

// mockStore is a configurable in-memory Store for handler tests.
// Each field is a function that can be set per-test. If nil, the method
// returns a zero value and nil error (or sql.ErrNoRows where noted).
type mockStore struct {
	createUser             func(context.Context, database.CreateUserParams) (database.User, error)
	getUserByEmail         func(context.Context, string) (database.User, error)
	updateUser             func(context.Context, database.UpdateUserParams) (database.UpdateUserRow, error)
	deleteAllUsers         func(context.Context) error
	upgradeUserToChirpyRed func(context.Context, uuid.UUID) (database.UpgradeUserToChirpyRedRow, error)
	createRefreshToken     func(context.Context, database.CreateRefreshTokenParams) error
	getRefreshToken        func(context.Context, string) (database.RefreshToken, error)
	revokeRefreshToken     func(context.Context, string) error
	createChirp            func(context.Context, database.CreateChirpParams) (database.CreateChirpRow, error)
	getAllChirps            func(context.Context) ([]database.GetAllChirpsRow, error)
	getAllChirpsDesc        func(context.Context) ([]database.GetAllChirpsDescRow, error)
	getChirpsByAuthor      func(context.Context, uuid.UUID) ([]database.GetChirpsByAuthorRow, error)
	getChirp               func(context.Context, uuid.UUID) (database.GetChirpRow, error)
	deleteChirp            func(context.Context, uuid.UUID) error
}

func (m *mockStore) CreateUser(ctx context.Context, arg database.CreateUserParams) (database.User, error) {
	if m.createUser != nil {
		return m.createUser(ctx, arg)
	}
	return database.User{}, nil
}
func (m *mockStore) GetUserByEmail(ctx context.Context, email string) (database.User, error) {
	if m.getUserByEmail != nil {
		return m.getUserByEmail(ctx, email)
	}
	return database.User{}, nil
}
func (m *mockStore) UpdateUser(ctx context.Context, arg database.UpdateUserParams) (database.UpdateUserRow, error) {
	if m.updateUser != nil {
		return m.updateUser(ctx, arg)
	}
	return database.UpdateUserRow{}, nil
}
func (m *mockStore) DeleteAllUsers(ctx context.Context) error {
	if m.deleteAllUsers != nil {
		return m.deleteAllUsers(ctx)
	}
	return nil
}
func (m *mockStore) UpgradeUserToChirpyRed(ctx context.Context, id uuid.UUID) (database.UpgradeUserToChirpyRedRow, error) {
	if m.upgradeUserToChirpyRed != nil {
		return m.upgradeUserToChirpyRed(ctx, id)
	}
	return database.UpgradeUserToChirpyRedRow{}, nil
}
func (m *mockStore) CreateRefreshToken(ctx context.Context, arg database.CreateRefreshTokenParams) error {
	if m.createRefreshToken != nil {
		return m.createRefreshToken(ctx, arg)
	}
	return nil
}
func (m *mockStore) GetRefreshToken(ctx context.Context, token string) (database.RefreshToken, error) {
	if m.getRefreshToken != nil {
		return m.getRefreshToken(ctx, token)
	}
	return database.RefreshToken{}, nil
}
func (m *mockStore) RevokeRefreshToken(ctx context.Context, token string) error {
	if m.revokeRefreshToken != nil {
		return m.revokeRefreshToken(ctx, token)
	}
	return nil
}
func (m *mockStore) CreateChirp(ctx context.Context, arg database.CreateChirpParams) (database.CreateChirpRow, error) {
	if m.createChirp != nil {
		return m.createChirp(ctx, arg)
	}
	return database.CreateChirpRow{}, nil
}
func (m *mockStore) GetAllChirps(ctx context.Context) ([]database.GetAllChirpsRow, error) {
	if m.getAllChirps != nil {
		return m.getAllChirps(ctx)
	}
	return nil, nil
}
func (m *mockStore) GetAllChirpsDesc(ctx context.Context) ([]database.GetAllChirpsDescRow, error) {
	if m.getAllChirpsDesc != nil {
		return m.getAllChirpsDesc(ctx)
	}
	return nil, nil
}
func (m *mockStore) GetChirpsByAuthor(ctx context.Context, userID uuid.UUID) ([]database.GetChirpsByAuthorRow, error) {
	if m.getChirpsByAuthor != nil {
		return m.getChirpsByAuthor(ctx, userID)
	}
	return nil, nil
}
func (m *mockStore) GetChirp(ctx context.Context, id uuid.UUID) (database.GetChirpRow, error) {
	if m.getChirp != nil {
		return m.getChirp(ctx, id)
	}
	return database.GetChirpRow{}, nil
}
func (m *mockStore) DeleteChirp(ctx context.Context, id uuid.UUID) error {
	if m.deleteChirp != nil {
		return m.deleteChirp(ctx, id)
	}
	return nil
}

// newTestHandler returns a Handler wired up with a mockStore and a fixed JWT secret.
func newTestHandler(store *mockStore) *Handler {
	return &Handler{
		DB:        store,
		JWTSecret: testJWTSecret,
		PolkaKey:  testPolkaKey,
		Platform:  "dev",
	}
}

const (
	testJWTSecret = "test-secret-key"
	testPolkaKey  = "test-polka-key"
)

// makeAuthHeader generates a valid Authorization: Bearer <jwt> header value
// for the given userID using the shared test secret.
func makeAuthHeader(userID uuid.UUID) string {
	tok, err := auth.MakeJWT(userID, testJWTSecret, time.Hour)
	if err != nil {
		panic("makeAuthHeader: " + err.Error())
	}
	return "Bearer " + tok
}
