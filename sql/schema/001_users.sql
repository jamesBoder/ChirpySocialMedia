-- +goose Up
CREATE TABLE users(
	id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
	created_at TIMESTAMP NOT NULL,
	updated_at TIMESTAMP NOT NULL,
	email TEXT UNIQUE NOT NULL
	
	
);

-- +goose Down
DROP TABLE users;
