# install reflex via `$ go get github.com/cespare/reflex`

RSA_PRIVATE_KEY="$(cat insecure_certs/pem.priv)" reflex -s  --regex='\.go$' -- go run *.go
