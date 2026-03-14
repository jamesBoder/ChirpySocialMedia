# Stage 1: build the React frontend
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# Stage 2: build the Go binary
FROM golang:1.24-alpine AS go-builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o chirpy .

# Stage 3: minimal runtime image
FROM alpine:latest
WORKDIR /app
COPY --from=go-builder /app/chirpy ./chirpy
COPY --from=frontend-builder /app/frontend/dist ./frontend/dist
EXPOSE 8888
CMD ["./chirpy"]
