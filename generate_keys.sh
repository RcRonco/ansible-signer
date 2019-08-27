openssl genrsa -out key.pem 4096
openssl rsa -in key.pem -outform PEM -pubout -out public.pem