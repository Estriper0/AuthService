FROM golang:1.25.1-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o main cmd/auth/main.go

RUN CGO_ENABLED=0 GOOS=linux go build -o migrate cmd/migrations/main.go

FROM alpine:latest AS migrations

WORKDIR /app

COPY --from=builder /app/configs/local.yaml /app/configs/prod.yaml ./configs/

COPY --from=builder /app/migrations ./migrations/

COPY --from=builder /app/migrate ./

FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/main ./

COPY --from=builder /app/configs/local.yaml /app/configs/prod.yaml ./configs/

EXPOSE 8080