FROM golang:1.15 AS builder

# Set the Current Working Directory inside the container
WORKDIR $GOPATH/src/github.com/ptcoffee/authorizer

COPY go.mod go.sum ./
RUN go mod download
COPY . ./
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix nocgo -o /authorizer .

# Run
FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /authorizer ./
EXPOSE 5000
ENTRYPOINT ["./authorizer"]