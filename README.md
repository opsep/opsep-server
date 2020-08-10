
## Setup

### Fetch repo:
```bash
$ git clone git@github.com:opsep/opsep-server.git && cd opsep-server
```

## Update local configs/secrets
If needed:
```bash
$ vim config_local.yaml
```

### Run the server
Use [reflex](https://github.com/cespare/reflex) to reload the server in development:
```bash
$ ./run_localhost.sh
```
(install via `$ go get github.com/cespare/reflex`)

### Test that it's working:
```bash
$ curl localhost:1323/ping
```

## Details


Encrypt a file locally to test decription with:
```bash
$ echo "{\"key\": \"00000000000000000000000000000000\"}" | openssl pkeyutl -encrypt -pubin -inkey insecurepub.crt -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 | base64 > symmetric_dek.asymm_enc
```

Calculate the hash of the file you just created (used as an integrity check):
```bash
$ cat symmetric_dek.asymm_enc | base64 --decode | shasum -a 256 
91402284b1b25828f4707c9e90d92bb9c06bebba22596bfa422197f1ba8f9ece  -
```
(used to make audit log easier)

Make an API call to decrypt the file you just made:
```bash
$ curl -X POST localhost:8080/api/v1/decrypt -H 'Content-Type: application/json' -d '{"asymmetric_ciphertext_b64":"'$(cat symmetric_dek.asymm_enc)'"}'
```


If you want a rough test of 429-ing, you can do this:
```bash
$ for i in {1..99}; do curl [...] "http://localhost:8080/api/v1/decrypt" ; done
```

### Other
Create an (insecure) RSA keypair in various formats:
```bash
$ openssl genrsa -out insecurepriv.pem 4096 && openssl rsa -in insecurepriv.pem -pubout -out insecurepub.crt && openssl pkcs8 -topk8 -nocrypt -inform PEM -outform DER -in insecurepriv.pem -out insecurepriv.formatted
Generating RSA private key, 4096 bit long modulus (2 primes)
...........................................++++
...............................++++
e is 65537 (0x010001)
writing RSA key
```

Query decryption API call logs:
```bash
$ curl https://www.secondguard.com/callz/100/0 | jq | grep String | uniq
```

Clean it up (`wc -l` is # of records):
```bash
$ curl -s https://www.secondguard.com/callz/99999/0 | jq '.[] .request_ip_address.String' | sort | uniq -c | sort -r | tee /dev/tty | wc -l
 106 "104.54.195.146"
  97 "68.173.52.193"
   6 "193.56.117.122"
   3 "2604:2000:1484:79:7571:c2ca:dc6d:825b"
   2 "72.182.102.4"
```
