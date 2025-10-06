-- sql
-- name: CreateChirp :one
INSERT INTO chirps (body, user_id)
VALUES ($1, $2)
RETURNING id, body, user_id, created_at, updated_at;

-- name: GetAllChirps :many
SELECT id, body, user_id, created_at, updated_at
FROM chirps
ORDER BY created_at ASC;

-- name: GetChirp :one
SELECT id, body, user_id, created_at, updated_at
FROM chirps
WHERE id = $1;