# pathbuster

A path-normalization pentesting tool using path replacements.

## Installation

Install rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Install pathbuster

```bash
cargo add pathbuster
```


## Usage

```bash
pathbuster 1.0
Blake Jacobs <blake@cyberlix.io
path-normalization pentesting tool

USAGE:
    pathbuster [OPTIONS] --url <url> --payloads <payloads> --deviation <deviation>

OPTIONS:
    -c, --concurrency <concurrency>
            The amount of concurrent requests [default: 50]

        --deviation <deviation>
            The distance between the responses [default: 3]

    -h, --help
            Print help information

        --match-status <match-status>
            [default: 200]

    -o, --out <out>
            The output file

    -p, --payloads <payloads>
            the file containing the traversal payloads [default: ]

    -r, --rate <rate>
            Maximum in-flight requests per second [default: 150]

        --stop-at-first-match <stop-at-first-match>
            stops execution flow on the first match [default: false]

    -u, --url <url>
            the url you would like to test

    -V, --version
            Print version information

    -w, --workers <workers>
            The amount of workers [default: 1]

        --wordlist <wordlist>
            the file containing the technology paths [default: .wordlist.tmp]
```

## Examples

Fingerprinting the proxy

```rust
$ pathbuster -u "https://example.com/api/{payload}/{payload}" -p traversals.txt --match-status 400 --deviation 2 -o output.txt
```

Directory Bruteforcing

```rust
$ pathbuster -u "https://example.com/api/{word}" --wordlist wordlist.txt --match-status 200 --deviation 2 -o output.txt
```

Discovery Process

```rust
$ pathbuster -u "https://example.com/api/v1/{payload}/{payload}/{payload}" -p traversals.txt --match-status 400,500 --deviation 2 -o paths.txt
$ pathbuster -u "https://example.com/api/v1/{payload}/{payload}" -p traversals.txt --match-status 404 --deviation 2 -o paths.txt
$ pathbuster -u "https://example.com/api/v1/{payload}/{payload}/{word}" -p traversals.txt --wordlist wordlist.txt --match-status 200 --deviation 2 -o paths.txt
```

![Screenshot](static/example.png)


## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License

[MIT](https://choosealicense.com/licenses/mit/)