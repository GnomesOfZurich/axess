use crate::authn::{
    backend::AuthnBackend,
    methods::{
        factor::{FactorInstance, FactorState},
        method::{MethodInstance, MethodState},
    },
    session::state::{AuthState, Data, PartialAuthState},
};

pub type AuthFactor<B> = FactorInstance<<B as AuthnBackend>::FactorId, <B as AuthnBackend>::UserId>;

pub type AuthFactorState<B> = FactorState<
    <B as AuthnBackend>::DataId,
    <B as AuthnBackend>::FactorId,
    <B as AuthnBackend>::TenantId,
    <B as AuthnBackend>::UserId,
>;

pub type AuthMethod<B> = MethodInstance<
    <B as AuthnBackend>::MethodId,
    <B as AuthnBackend>::FactorId,
    <B as AuthnBackend>::UserId,
>;

pub type AuthMethodState<B> = MethodState<
    <B as AuthnBackend>::MethodId,
    <B as AuthnBackend>::FactorId,
    <B as AuthnBackend>::TenantId,
    <B as AuthnBackend>::UserId,
>;

pub type PartialState<B> = PartialAuthState<
    <B as AuthnBackend>::MethodId,
    <B as AuthnBackend>::FactorId,
    <B as AuthnBackend>::UserId,
>;

pub type SessionState<B> = AuthState<
    <B as AuthnBackend>::MethodId,
    <B as AuthnBackend>::FactorId,
    <B as AuthnBackend>::UserId,
>;

pub type SessionData<B> = Data<
    <B as AuthnBackend>::MethodId,
    <B as AuthnBackend>::FactorId,
    <B as AuthnBackend>::UserId,
    <B as AuthnBackend>::TenantId,
>;
