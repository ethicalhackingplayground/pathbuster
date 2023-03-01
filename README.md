# pathbuster

A path-normalization pentesting tool using path replacements.

<p align="center">
  <a href="/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg"/></a>
  <a href="http://golang.org"><img src="https://img.shields.io/badge/Made%20with-Go-1f425f.svg"/></a>
  <a href="https://github.com/ethicalhackingplayground/pathmapper/issues"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat"></a>
  <a href="https://twitter.com/z0idsec"><img src="https://img.shields.io/twitter/follow/z0idsec.svg?logo=twitter"></a>
  <a href="https://discord.gg/MQWCem5b"><img src="https://img.shields.io/discord/862900124740616192.svg?logo=discord"></a>
  <br>
  <b>All your proxies are belong to us</b>
</p>

---

<p align="center">
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#examples">Examples</a> •
  <a href="#contributing">Contributing</a> •
  <a href="#license">License</a> •
  <a href="https://discord.gg/MQWCem5b">Join Discord</a> 
</p>

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

```sh
pathbuster -h
```

<details>
<summary> 👉 pathbuster help menu 👈</summary>

```
USAGE:
    pathbuster [OPTIONS] --url <url> --payloads <payloads> --paths <paths> --deviation <deviation>

OPTIONS:
    -c, --concurrency <concurrency>
            The amount of concurrent requests [default: 100]

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

        --paths <paths>
            The list of routes (crawl the host to collect routes) [default: .paths.tmp]

    -r, --rate <rate>
            Maximum in-flight requests per second [default: 1000]

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
$ pathbuster -u "https://example.com/{paths}/{payloads}" --payloads traversals.txt --paths paths.txt --match-status 400 --deviation 2 -o output.txt
```

Discovery Process

```rust
$ pathbuster -u "https://example.com/{paths}/{payloads}/{words}" --payloads traversals.txt --paths paths.txt --wordlist raft-medium-directories.txt --match-status 200 --deviation 2 -o output.txt
```

![Screenshot](static/example.png)


## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License

Pathbuster is distributed under [MIT License](https://github.com/ethicalhackingplayground/pathbuster/blob/main/LICENSE)

<h1 align="left">
  <a href="https://discord.gg/MQWCem5b"><img src="static/Join-Discord.png" width="380" alt="Join Discord"></a>
</h1>