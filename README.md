# url2ip

A lightweight command-line tool that resolves a URL or hostname to its IP addresses and, when requested, checks selected TCP ports. It uses only the Python standard library.

## Features

- Resolves HTTP(S) URLs, bare hostnames, IPv4 addresses, and IPv6 addresses.
- Optionally checks explicitly selected TCP ports and ranges.
- Uses bounded concurrency, with a maximum of 64 workers.
- Prints readable terminal output or structured JSON.
- Has no third-party runtime dependencies.

## Requirements

- Python 3.10 or newer

## Install

From a clone of this repository:

```console
python -m pip install .
```

For editable development installation:

```console
python -m pip install -e .
```

Alternatively, run the module directly from the repository without installing:

```console
python -m src.url2ip https://example.com
```

## Usage

Resolve a hostname:

```console
url2ip https://example.com
```

Check only ports you specify:

```console
url2ip example.com --ports 22,80,443
url2ip https://example.com:8443/health --ports 8000-8010 --timeout 0.8
```

Get JSON output:

```console
url2ip example.com --ports 80,443 --json
```

Run the test suite:

```console
python -m pip install -e .
python -m unittest discover -s tests -v
```

### Port states

- `open`: a TCP connection was accepted.
- `closed_or_filtered`: the connection could not be established. A firewall, timeout, or unreachable host can produce the same result, so this does not prove that a port is closed.

Port scans make network connections. **Only scan systems you own or have explicit permission to test.** Keep scans limited to the ports you need; this tool caps each port list at 256 unique ports, total address/port checks at 512, and connection concurrency at 64.

## Scope

This is a basic TCP connect checker, not a vulnerability scanner or a substitute for a full network inventory tool. Results depend on DNS responses, network routing, and firewall policy.

## License

MIT. See [LICENSE](LICENSE).
