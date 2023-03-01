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

```rust
pathbuster -u "https://example.com/api/{payload}" -p payloads\traversals.txt --deviation 2 -o output.txt
```

![Screenshot](static/example.png)


## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License

[MIT](https://choosealicense.com/licenses/mit/)