# Certer

Certer is a web-based application designed to streamline the process of generating Certificate Signing Requests (CSRs) and automatically requesting the corresponding SSL/TLS certificates from your Certificate Authority (CA). It provides a user-friendly, multi-step interface for inputting certificate details and handles the underlying OpenSSL commands and CA interactions, simplifying certificate management.

## ToDo
- [x] Generate CSR
- [x] Use existing key
- [ ] Integrate LDAP Auth


## Installation
You can install put the files directly onto your webserver. I use docker.

```bash
mv docker-compose.sample.yml docker-compose.yml
docker compose up -d
```

## Usage
Open [http://127.0.0.1](http://127.0.0.1) and login with admin:password

## Contributing
Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[LICENSE](LICENSE)