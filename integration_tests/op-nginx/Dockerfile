FROM nginx:1.27-alpine

# Generate a self-signed certificate for the `op-nginx` hostname. The
# conformance suite's headless browser (HtmlUnit) and its API client both
# have TLS verification disabled when talking to the OP, so the self-signed
# cert is fine for the integration tests.
RUN apk add --no-cache openssl \
    && openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout /etc/ssl/private/op-nginx.key \
        -out /etc/ssl/certs/op-nginx.crt \
        -subj "/CN=op-nginx" \
    && apk del openssl

COPY nginx.conf /etc/nginx/nginx.conf
