# Safe DNS Resolver

Safe DNS Resolver is a program which runs a DNS server on your machine and resolves DNS requests.
It can be configured to filter domain names. It also caches already made requests.

## Requirements
 - Python3
 - dnslib
 - dnspython

To install them run:
```
$ python3 -m pip install -r requirements.txt
```

## Usage
To run program use:
```
$ sudo python3 src/main.py
```

Which will start the server on your localhost

## Configuration
You can specify custom records for resolving in `config.txt` file.
Use the following format:
```
DOMAIN TYPE IP
```
Where DOMAIN is the domain host, TYPE is the type record, and IP is the data of the record.