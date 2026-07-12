FROM golang:1.26.5-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o auth  ./cmd/



# RUNNER IMAGE
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata curl
WORKDIR /root/
COPY --from=builder /app/auth .
EXPOSE 8080
CMD ["./auth"]
