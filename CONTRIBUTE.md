# Contributing to Axess

Thank you for your interest in contributing to Axess!
We welcome bug reports, feature requests, documentation improvements, and code contributions.

## 📝 How to Contribute

1. **Fork the repository** and create your branch from `main`.
2. **Write clear, concise code** following Rust’s idioms and our [coding guidelines](.github/copilot-instructions.md).
3. **Document public APIs** and add relevant examples.
4. **Write unit tests** for all new features and bug fixes.
5. **Run all tests** before submitting your pull request:
   ```bash
   cargo test --workspace --all-features
   ```
6. **Format your code** using `rustfmt`:
   ```bash
   cargo fmt --all
   ```
7. **Open a pull request** with a clear description of your changes.

## 🧑‍💻 Coding Guidelines

- Use idiomatic Rust patterns and naming conventions.
- Prefer traits for abstraction.
- Use `async`/`await` for IO operations.
- Use the `thiserror` crate for error handling.
- Use the `tracing` crate for logging and tracing.
- Ensure code supports Deterministic Simulation Testing (DST).
- Add documentation for all public items.

See [.github/copilot-instructions.md](.github/copilot-instructions.md) for more details.

## 🐛 Bug Reports & Feature Requests

- Please use [GitHub Issues](https://github.com/gnomesofzurich/axess/issues) for bug reports and feature requests.
- Include as much detail as possible (steps to reproduce, expected behavior, environment).

## 📦 Project Structure

- `axess/` — Main library and middleware
- `axess-core/` — Core types, traits, and utilities
- `axess-factors/` — Factor implementations
- `axess-macros/` — Procedural macros
- `examples/` — Example applications

## 🛡️ Security

If you discover a security vulnerability, please report it privately by emailing [security@gnomes.ch](mailto:security@gnomes.ch) or opening a private issue.

## 📃 License

By contributing, you agree that your contributions will be licensed under the [MIT License](./LICENSE).

## 🙋 Maintainer Availability

Axess is currently not maintained by a large (or full-time) support organization.
We will do our best to review issues and pull requests in a timely manner, but please be patient if responses are delayed.

## 🤝 Community Standards

Please be respectful and constructive in all communications.
See [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) for details.

---

Thank you for helping make Axess better!