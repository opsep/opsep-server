# install reflex via `$ go get github.com/cespare/reflex`

SERVER_PORT=8080 RSA_PRIVATE_KEY="$(cat insecure_certs/pem.priv)" reflex -s  --regex=\.db -- go run *.go
