# webserver
```bash
openssl genpkey -algorithm RSA -out server.key
openssl req -new -key server.key -out server.csr
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.pem
```
## To test Server it's possible to use CURL:
```bash
# HTTP2
curl --http2  --cacert /path/to/certificate/server.pem -X POST https://localhost:8080 -d '{"test":"test"}' # for test without debug info
curl --http2  --cacert /Users/kirillzhukov/Downloads/server.pem -X POST https://localhost:8080 -d '{"test":"test"}' -v # for test with debug info

# HTTP1
curl -0  --cacert /path/to/certificate/server.pem -X POST https://localhost:8080 -d '{"test":"test"}' # for test without debug info
curl -0  --cacert /Users/kirillzhukov/Downloads/server.pem -X POST https://localhost:8080 -d '{"test":"test"}' -v # for test with debug info 
```

