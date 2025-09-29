-- +goose Up
ALTER TABLE chirps
ADD CONSTRAINT chirps_user_id_fkey
FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

-- +goose Down
ALTER TABLE chirps
DROP CONSTRAINT chirps_user_id_fkey;