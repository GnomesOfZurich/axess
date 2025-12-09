//! Shared type aliases for backend-specific authentication types.
//!
//! These aliases map an [`AuthnBackend`](crate::authn::backend::AuthnBackend)’s
//! associated identifiers to the generic session and factor structures used
//! throughout Axess, keeping call sites concise.

use crate::authn::{
    backend::AuthnBackend,
    // scope::AuthnScope,
    methods::{
        MethodInstance, MethodState,
        factor::{FactorInstance, FactorState},
    },
    session::state::{AuthState, Data, PartialAuthState},
};

pub type AuthFactor<B> = FactorInstance<<B as AuthnBackend>::AuthId, <B as AuthnBackend>::UserId>;

pub type AuthFactorState<B> = FactorState<
    <B as AuthnBackend>::AuthId,
    <B as AuthnBackend>::TenantId,
    <B as AuthnBackend>::UserId,
>;

pub type AuthMethod<B> = MethodInstance<<B as AuthnBackend>::AuthId, <B as AuthnBackend>::UserId>;

pub type AuthMethodState<B> = MethodState<
    <B as AuthnBackend>::AuthId,
    <B as AuthnBackend>::TenantId,
    <B as AuthnBackend>::UserId,
>;

pub type PartialState<B> =
    PartialAuthState<<B as AuthnBackend>::AuthId, <B as AuthnBackend>::UserId>;

pub type SessionState<B> = AuthState<<B as AuthnBackend>::AuthId, <B as AuthnBackend>::UserId>;

pub type SessionData<B> =
    Data<<B as AuthnBackend>::AuthId, <B as AuthnBackend>::TenantId, <B as AuthnBackend>::UserId>;

// pub type SessionScope<B> = AuthnScope<
//     <B as AuthnBackend>::TenantId,
//     <B as AuthnBackend>::UserId,
// >;
