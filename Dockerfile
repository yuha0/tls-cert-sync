FROM golang:1.22 AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 go build -ldflags "-X github.com/tlscertsync/cmd.Version=${VERSION}" -o /tlscertsync .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /tlscertsync /tlscertsync
ENTRYPOINT ["/tlscertsync"]
