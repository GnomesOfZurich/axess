# Axess

## 🔆 Authentication and Authorization made easy for Axum webservers

**Axess** is an authentication and authorization library for the [Axum](https://github.com/tokio-rs/axum) web framework in Rust. It provides robust and modular middleware and extractors, for secure, session-based, policy-driven access control of web services.

The authentication system is built on top of the [tower-sessions](https://github.com/maxcountryman/tower-sessions) crate and was originally intended as a simple fork of the [axum-login](https://github.com/maxcountryman/axum-login) crate. The justification for creating *Axess* was that the authentication features of *axum-login* at the time unfortunately didn't support 2FA easily out-of-the-box and and that too many of its' useful inner workings was hidden as privates. Also, its' authorization feature doesn't support Relationship-Based Access Control models nor would it be easy to make use of Cedar Policy without a lot of further customizations.

The default authorization features of Axess is built on top of [Cedar Policy](https://www.cedarpolicy.com/), a domain specific language and related tooling that were all originally developed and open sourced by Amazon Web Services (*AWS*). This makes the library somewhat agnostic to whether a user's project needs to support *Role Based Access Control* (__RBAC__ ), *Attribute Based Access Control* (__ABAC__ ), or *Relationship Based Access Control* (__ReBAC__). Source Code for the Cedar project can be found on GitHub [here](https://github.com/cedar-policy). Additionally, features related to **Tracing ID** and **Request ID** management were added to the project as these were found to be useful and nice to have during testing.


## 💡 Concepts

- **Authentication Middleware:** Easily authenticate requests using sessions and pluggable backends.
- **Authorization via Cedar Policy:** Integrates with [Cedar](https://cedarpolicy.com/) for flexible, fine-grained authorization policies (supporting ABAC, RBAC and ReBAC).
- **Request Tracing & ID Generation:** Built-in support for request IDs and tracing.
- **Extensible Storage:** Abstract storage interfaces for authentication policies, sessions and user data.
- **Idiomatic Rust:** Follows Rust best practices, async-first APIs, and strong type safety.
- **Deterministic Simulation Testing (DST):** Designed for testability and reproducibility.


## 📦 Installation and Getting Started
1. To use the Axess in your project, run the usual:
```bash
cargo add axess```

from your command line or add the following to your `Cargo.toml` file:
```toml
[dependencies]
axess = { version="0.0.1", features=["full"]}
```
2. Define your Cedar policies if interested in authorization. This is a feature protected by feature toggle `authz` (part of the `default` configuration).
3. Configure authentication and authorization middleware.
4. Secure your Axum routes.

## 🤸 Example Usage
Create a minimal Axum webb applicatiob project and initiate the axess layers of interest from some backend storage and session cache of your choice. The router layers then provide session based authentication for your services:
```rust
use axess::authn::Authenticator;
use axess::authz::Authorizer;
use axess::middleware::AxessLayer;
use axum::{Router, routing::get};

let authenticator = Authenticator::new("secret");
let authorizer = Authorizer::from_policy_file("policy.cedar");

let app = Router::new()
    .route("/protected", get(protected_handler))
    .layer(AxessLayer::new(authenticator, authorizer));
```


## 📚 Documentation

- [API Docs](https://docs.rs/axess)
- [Examples](examples/) 
- [Cedar Policy Language](https://cedarpolicy.com/)

## ☑️ Features
- `authn`: Enable **Authentication** layer and related extractors.
- `authz`: Enable **Authorization** layer via Cedar Policy.
- `admin`: Enable **administrative** capabilities for managing users, tenants and various authentication parameters.
- `request_id`: Enable addition of **Request ID** into headers.
- `trace_id`: Enables helpers related to **Tracing ID** and tracing.
- `valkey`: Enables support for **Valkey** (Redis-compatible) session and storage backends.


## 📃 License
Licensed under the MIT License.

---

*Axess: Secure, policy-driven authentication and authorization for Axum.*