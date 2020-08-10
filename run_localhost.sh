SERVER_PORT=8080 RSA_PRIVATE_KEY="$(cat insecurepriv.pem)" reflex -s  --inverse-regex=\.db -- go run ./cmd/web/ 
