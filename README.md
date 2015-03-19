# journal2gelf

Export structured log records from the systemd journal and send them to a Graylog2 server as GELF messages.

In contrast to [semi-official script](https://github.com/systemd/journal2gelf) this doesn't start any additional
processes, doesn't parse json. It communicates to journald directly via socket using official [python-systemd
library](https://github.com/systemd/python-systemd).

## Installation

Install dependencies:

```
$ pip install gelfclient
```

## Usage

```
$ ./journal2gelf.py --help
usage: journal2gelf.py [-h] [-e FIELD] [-E] [--debug] [--merge] [--dry-run]
                       target

Export structured log records from the systemd journal and send them to a
Graylog2 server as GELF messages.

positional arguments:
  target                graylog2 server host:port

optional arguments:
  -h, --help            show this help message and exit
  -e FIELD, --exclude FIELD
                        exclude journal field FIELD
  -E, --no-defaults     don't exclude fields, excluded by default
  --debug               print GELF jsons to stdout
  --merge               send existing records first
  --dry-run             don't send anything to graylog
```
