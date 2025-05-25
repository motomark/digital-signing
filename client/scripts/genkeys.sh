# Private Key (PEM)
openssl genpkey -algorithm RSA -out client-private.pem -pkeyopt rsa_keygen_bits:2048

# Public Key (PEM)
openssl rsa -pubout -in client-private.pem -out client-public.pem