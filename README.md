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
cargo add axess
```

from your command line or add the following to your `Cargo.toml` file:
```toml
[dependencies]
axess = { version="0.0.10", features=["full"]}
```
2. Define your Cedar policies if interested in authorization. This is a feature protected by feature toggle `authz` (part of the `default` configuration).
3. Configure authentication and authorization middleware.
4. Secure your Axum routes.

## 🤸 Example Usage
Create a minimal Axum web application project and initiate the axess layers of interest from some backend storage and session cache of your choice. The router layers then provide session based authentication for your services:
```rust
use axess::{AuthnServiceBuilder, AuthSession, SessionRegistryStore, SystemRng, login_required};
use axum::{Router, routing::get};
use tower_sessions_sqlx_store::SqliteStore;
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::net::TcpListener;
use crate::{
    handlers::{protected_handler, login_handler, logout_handler, hello_world, // Your route handlers
    models::OurBackend, // Your custom backend implementation, handling interactions with the database
};

type Session = AuthSession<OurBackend, SessionRegistryStore<SqliteStore>, SystemRng>;

// Create backend and session store
let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
let backend = Arc::new(OurBackend::new(pool.clone()));
let session_store = SqliteStore::new(pool.clone());
let session_registry = Arc::new(SessionRegistryStore::new(session_store.clone(), 100, None, None));

// Build the authentication layer
let auth_layer = AuthnServiceBuilder::new(backend.clone(), session_layer)
    .with_session_registry(session_registry.clone())
    .build();


// Protected routes require authentication
let protected_router = Router::new()
    .route("/main", get(protected_handler))
    .route_layer(login_required!(Arc<Session>, "/login"));

// Auth routes (login/logout) may need backend state
let public_router = Router::new()
    .route("/", get(hello_world))
    .route("/login", get(login_handler))
    .route("/logout", get(logout_handler));

// Assemble the router
let app = Router::new()
    .merge(protected_router)
    .merge(public_router)
    .layer(auth_layer);

// Start serving the application.
let address = "127.0.0.1:3000".parse()?;
let listener = TcpListener::bind(address).await?;
axum::serve(listener, app_router.into_make_service()).await?;
```

## ☑️ Features
- `authn`: Enable **Authentication** layer and related extractors.
- `authz`: Enable **Authorization** layer via Cedar Policy.
- `admin`: Enable **administrative** some additional capabilities for managing users, tenants and various authentication parameters.
- `request_id`: Enable addition of **Request ID** into headers.
- `trace_id`: Enables helpers related to **Tracing ID** and tracing.
- `memory`: Enables **in-memory** session and storage backends for development and testing.
- `valkey`: Enables support for **Valkey** (Redis-compatible) session and storage backends.


## 🗂 Project Structure

- `axess/` — Main library and middleware
- `axess-core/` — Core types, traits, and utilities
- `axess-factors/` — Factor implementations (password, TOTP, HOTP)
- `axess-macros/` — Procedural macros for Axum integration
- `examples/` — Example Axum applications

## 🔗 Quick Links

- [axess-core](./axess-core)
- [axess-factors](./axess-factors)
- [axess-macros](./axess-macros)
- [Examples](./examples)

## 📚 Documentation

- [API Docs](https://docs.rs/axess)
- [Examples](examples/) 
- [Cedar Policy Language](https://cedarpolicy.com/)

### Authentication Flow:

```mermaid
---
title: Authentication Flow
---
flowchart LR
    Start((Start)):::starter --> LoginForm[/Form:</br>Login Page/]:::form & SignupForm[/Form:</br>Signup Page/]:::form
    AuthFailure((Authentication</br>Failed)):::failure -->|Not Authenticated| End((End)):::ender
    AuthFailure -->|Re-route to Login| LoginForm
    AuthnSuccess -->|Authenticated| End

    Login:::process
    Signup:::process
    FactorSetup:::process

    subgraph Login [ User Login Flow ]
        direction LR
        LoginForm -->|Submit Form| ResolveUserTenant((Resolve</br>Tenant & User</br>from Backend))
        ResolveUserTenant -->|Tenant/User Not Found| LoginForm
        ResolveUserTenant -->|Ok| GetAuthMethod((Query Auth Method</br>for Scope))
        GetAuthMethod -->|No Method Found| LoginForm
        GetAuthMethod -->|Ok| StartAuthSession((Start Auth Session</br>Set State: PartialAuthn</br>Register in Registry))
        StartAuthSession --> ValidateState{Validate</br>Session State</br>Transition}
        ValidateState -->|Invalid State| AuthFailure
        ValidateState -->|Valid| QueryFactorState((Query Factor State</br>from Backend</br>for Scope))
        QueryFactorState --> VerifyCredentials((Verify Credentials</br>vs Stored Config))
        VerifyCredentials -->|Ok| ApplyFactor((Apply Factor</br>Update State))
        VerifyCredentials -->|Failed| FailedFactorVerification{Failed</br>Factor Verification</br>try again?}
        ApplyFactor --> VerifyMoreFactors{More Factors</br>to Verify?}
        VerifyMoreFactors -->|Yes| RedirectToVerify((Redirect to</br>Factor</br>Verification))
        RedirectToVerify --> MfaForm[/Form:</br>Verify Next Factor/]:::form
        MfaForm -->|Submit Form| ValidateState
        VerifyMoreFactors -->|No, Done!| CycleSessionID((Cycle Session ID</br>for Security))
        CycleSessionID --> GenerateHash((Generate</br>Session Hash))
        GenerateHash --> UpdateRegistry((Update Session</br>in Registry))
        UpdateRegistry --> InvalidateOldSession((Invalidate Old</br>Session ID))
        InvalidateOldSession --> SaveSessionData((Save Session Data</br>State: Authenticated))
        SaveSessionData --> CompletedLogin(Login Successful):::success
        FailedFactorVerification -->|Yes, Retry| QueryFactorState
        FailedFactorVerification -->|No, Max Attempts| ExponentialLockout((Apply Exponential</br>User Lockout</br>Invalidate Session))
        ExponentialLockout -->|Cancel Session| AuthFailure
        CompletedLogin --> AuthnSuccess((Authentication</br>Completed)):::success
    end

    subgraph FactorSetup [ Authn Factor Setup Flow ]
        direction LR
        VerifyMoreFactors -->|Yes, Factor</br>Needs Setup| CheckAuthenticated{User Already</br>Authenticated?}
        CheckAuthenticated -->|No| AuthFailure
        CheckAuthenticated -->|Yes| RedirectToSetup((Redirect to</br>Factor Setup))
        RedirectToSetup --> SetupNextExpectedFactor[/Form:</br>Setup Expected Factor/]:::form
        SetupNextExpectedFactor -->|Submit Form| ValidateSetupForm((Validate</br>Setup Form))
        ValidateSetupForm --> EvaluateFactorSetup{Evaluate</br>Factor Setup</br>Credentials}
        EvaluateFactorSetup -->|Ok| UpsertFactorState((Upsert Factor State</br>to Backend</br>with Config))
        UpsertFactorState --> SetupMoreFactors{More Factors</br>to Setup?}
        EvaluateFactorSetup -->|Failed| FailedFactorSetup{Failed</br>Factor Setup</br>Try Again?}
        FailedFactorSetup -->|Retry| RedirectToSetup
        FailedFactorSetup -->|Cancel Flow| AuthFailure
        QueryFactorState -->|Factor State</br>Not Found| CheckAuthenticated
        SetupMoreFactors -->|Yes| RedirectToSetup
        SetupMoreFactors -->|No| RedirectToVerify
    end

    subgraph Signup [ User Signup Flow - Not Yet Implemented ]
        direction LR
        SignupForm -->|Submit Form| AttemptCreateUserAccount(Create</br>New User Account</br>in Backend)
        AttemptCreateUserAccount -->|Failed| SignupForm
        AttemptCreateUserAccount -->|Ok| GenerateSignupVerificationEmail((Generate</br>Verification Email))
        GenerateSignupVerificationEmail -->|Send Email| UserEmailInbox[User's Email Inbox</br>Verification Link]
        UserEmailInbox --> VerifyEmail[/Form:</br>Verify Email/]:::form
        VerifyEmail -->|Submit Form| CreateUserDefaultAuth((Setup</br>Default Authn</br>Method))
        CreateUserDefaultAuth --> SetupMoreFactors
        SetupMoreFactors -->|No, Done!| CompletedSignup(Signup Successful):::success
        CompletedSignup --> AuthnSuccess
    end

classDef ender fill:#ffffff,stroke:#ffa0a0,stroke-width:0.4em,color:#ffa0a0,font-size:1.5em;
classDef starter fill:#ffffff,stroke:#000,stroke-width:3px,color:#00a000,font-size:1.5em;
classDef form fill:#a0d0ff,stroke:#000,stroke-width:3px,color:#0000bb;
classDef success stroke:#a0ffa0,stroke-width:3px,color:#a0ffa0;
classDef failure stroke:#ffa0a0,stroke-width:3px,color:#ffa0a0;
classDef process align:left;
```

## 📃 License
Licensed under the [MIT License](./LICENSE).

## 🛡️ Security

Axess is designed for secure authentication and authorization in web applications.  
If you discover a security vulnerability, please report it responsibly:

- **Reporting:**  
  Please email security@gnomes.ch or open a private issue on GitHub.
- **Best Practices:**  
  - Always use HTTPS in production.
  - Keep dependencies up to date.
  - Review your Cedar policies and backend configuration for least privilege.
- **Caveats:**  
  - Axess is provided as-is; review and test before deploying to production.
  - Multi-factor authentication is recommended for sensitive applications.
  - Session and credential storage should be secured according to your threat model.

For more details, see [SECURITY.md](./SECURITY.md).

---

*Axess: Secure, policy-driven authentication and authorization for Axum.*