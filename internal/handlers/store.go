package handlers

import (
	"context"

	"github.com/google/uuid"
	"github.com/jamesboder/ChirpySocialMedia/internal/database"
)

// Store is the interface the Handler uses to interact with the database.
// *database.Queries satisfies this interface, and a mockStore can be used in tests.
type Store interface {
	// Users
	CreateUser(ctx context.Context, arg database.CreateUserParams) (database.User, error)
	GetUserByEmail(ctx context.Context, email string) (database.User, error)
	UpdateUser(ctx context.Context, arg database.UpdateUserParams) (database.UpdateUserRow, error)
	DeleteAllUsers(ctx context.Context) error
	UpgradeUserToChirpyRed(ctx context.Context, id uuid.UUID) (database.UpgradeUserToChirpyRedRow, error)

	// Refresh tokens
	CreateRefreshToken(ctx context.Context, arg database.CreateRefreshTokenParams) error
	GetRefreshToken(ctx context.Context, token string) (database.RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, token string) error

	// Chirps
	CreateChirp(ctx context.Context, arg database.CreateChirpParams) (database.CreateChirpRow, error)
	GetAllChirps(ctx context.Context) ([]database.GetAllChirpsRow, error)
	GetAllChirpsDesc(ctx context.Context) ([]database.GetAllChirpsDescRow, error)
	GetChirpsByAuthor(ctx context.Context, userID uuid.UUID) ([]database.GetChirpsByAuthorRow, error)
	GetChirp(ctx context.Context, id uuid.UUID) (database.GetChirpRow, error)
	DeleteChirp(ctx context.Context, id uuid.UUID) error
}
