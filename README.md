
<h1 align="center">pathbuster
  <br>
</h1>

<h4 align="center">A path-normalization pentesting tool using path replacements.</h4>

<p align="center">
  <a href="/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg"/></a>
  <a href="http://golang.org"><img src="https://camo.githubusercontent.com/2ed8a73e5c5d21391f6dfc3ed93f70470c1d4ccf32824d96f943420163df9963/68747470733a2f2f696d672e736869656c64732e696f2f62616467652f4c616e67756167652d527573742d3138313731373f636f6c6f723d726564"/></a>
  <a href="https://github.com/ethicalhackingplayground/pathmbuster/issues"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat"></a>
  <a href="https://twitter.com/z0idsec"><img src="https://img.shields.io/twitter/follow/z0idsec.svg?logo=twitter"></a>
  <a href="https://discord.gg/MQWCem5b"><img src="https://img.shields.io/discord/862900124740616192.svg?logo=discord"></a>
  <br>
</p>

---

<p align="center">
  <a href="#todos">Todos</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#examples">Examples</a> •
  <a href="#contributing">Contributing</a> •
  <a href="#license">License</a> •
  <a href="https://discord.gg/MQWCem5b">Join Discord</a> 
</p>

---

### Todos

- [x] Implement multiple host scanning using the replacement `{hosts}`.
- [x] Implement **--filter-status** which will filter the status codes.
- [x] Implement **--filter-body-size** which will filter the response sizes.
- [x] Implement **--drop-after-fail** which will ignore requests with the same response code multiple times in a row.
---

## Installation

Install rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Install pathbuster

```bash
cargo install pathbuster
```


## Usage

```bash
pathbuster -h
```

This command will show the tool's help information and present a list of all the switches that are available.

```
USAGE:
    pathbuster [OPTIONS] --url <url> --payloads <payloads> --deviation <deviation>

OPTIONS:
    -c, --concurrency <concurrency>
            The amount of concurrent requests [default: 100]

        --deviation <deviation>
            The distance between the responses [default: 3]

        --drop-after-fail <drop-after-fail>
            ignore requests with the same response code multiple times in a row [default: 302,301]

        --filter-body-size <filter-body-size>
            [default: 0]

        --filter-status <filter-status>
            [default: 302,301]

    -h, --help
            Print help information

        --hosts <hosts>
            the file containing the list of root domains [default: ]

        --match-status <match-status>
            [default: 200]

    -o, --out <out>
            The output file

        --paths <paths>
            the file containing the list of routes (crawl the host to collect routes) [default: ]

        --payloads <payloads>
            the file containing the traversal payloads [default: ./payloads/traversals.txt]

    -r, --rate <rate>
            Maximum in-flight requests per second [default: 1000]

    -u, --url <url>
            the url you would like to test

    -V, --version
            Print version information

    -w, --workers <workers>
            The amount of workers [default: 1]

        --wordlist <wordlist>
            the file containing the technology paths [default: ]
```

## Flags

| Flag             | Description                                                                |
| ----------------- | ------------------------------------------------------------------ |
| --url |  url you would like to test
| --paths | file containing the route place holder is **{paths}** |
| --payloads | file containing the payloads place holder is **{payloads}** |
| --hosts |  file containing the root domains place holder is **{hosts}** |
| --wordlist |  file containing the technology wordlist **{words}** |
| --match-status |  status code used to match internal responses |
| --filter-body-size |  used to filter the response body like ffuf  |
| --filter-status |  used to filter the response status code like ffuf  |
| --drop-after-fail |  specify a status code to ignore if it reoccurs more than 5 times in a row  |
| --deviation |  used to compare responses for deviations compares ../internalpath to /internalpath  |
| --rate | used set the maximum in-flight requests per second |
| --workers | number of workers to process the jobs |
| --concurrency | number of threads to be used for processing |
| --out | save output to a file |
| --help | prints help information |
| --version | prints version information |

## Examples

Fingerprinting the proxy

```rust
$ pathbuster -u "https://example.com/{paths}/{payloads}" --payloads traversals.txt --paths paths.txt --match-status 400 --deviation 2 -o output.txt
```

Discovery process for a single URL

```rust
$ pathbuster -u "https://example.com/{paths}/{payloads}/{words}" --payloads traversals.txt --paths paths.txt --wordlist raft-medium-directories.txt --match-status 200 --deviation 2 -o output.txt
```

Discovery process using host replacements

```rust
$ pathbuster -u "https://{hosts}/{paths}/{payloads}/{words}" --hosts roots.txt --payloads traversals.txt --paths paths.txt --wordlist raft-medium-directories.txt --match-status 200 --deviation 2 -o output.txt
```

![Screenshot](static/example.png)


## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

Please make sure to update tests as appropriate.


## Support

For support, email blake@cyberlix.io or join our Discord group.

## License

Pathbuster is distributed under [MIT License](https://github.com/ethicalhackingplayground/pathbuster/blob/main/LICENSE)