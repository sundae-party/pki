# pki

A smple cli tool to create and signe CA, server cert, client cert for mTLS.

## Usage

Use --help flag to display available flags and options:

```bash
./pki_darwin-amd64
A smple cli tool to create and signe CA, server cert, client cert for mTLS

Usage:
  pki [command]

Available Commands:
  ca          Create new self signed CA
  clientCert  Manage client certificate
  help        Help about any command
  read        Show info about a cert
  serverCert  Create new server cert and key

Flags:
      --config string   config file (default is $HOME/.pki.yaml)
  -h, --help            help for pki

Use "pki [command] --help" for more information about a command.
```
