## RNU: Simple NS update server written in Rust

## Setup

The server can be configured using the following environment variables:

- `RNU_DEBUG` enables debug mode and just outputs performed operation to stdout
- `RNU_AUTH_FILE` (default "keys") File that contains pairs of API key and domain
- `RNU_HOST` (default "127.0.0.1") address to bind to
- `RNU_PORT` (default "3000") port to bind to

## Usage

Send a GET request to:
```
http://<host>:<port>/update?key=<key>&domain=<domain>&ip=<ipv4>&ipv6=<ipv6>
```

You need to specify at least one of the IP parameters. 
