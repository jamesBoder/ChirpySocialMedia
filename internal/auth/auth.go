package auth

import "github.com/alexedwards/argon2id"

func HashPassword(password string) (string, error) {
	// Hash password using argon2id.CreateHash
	params := argon2id.DefaultParams
	hash, err := argon2id.CreateHash(password, params)
	if err != nil {
		return "", err
	}
	return hash, nil

}

func ComparePasswordHash(password, hash string) (bool, error) {
	// Compare password and hash using argon2id.ComparePasswordAndHash
	return argon2id.ComparePasswordAndHash(password, hash)
}
