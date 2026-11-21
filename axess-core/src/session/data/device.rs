//! The session's device and its key binding, as they hold for the person at
//! the session's browser.
//!
//! A key binding is made for one person, the owner of the device: the
//! administrator while the session is an impersonation, else the signed-in
//! user. It is in force only while that person is the one at the browser of
//! the session. A binding that is not in force is not a binding to any
//! reader, and the session layer drops it from the row at the next write.
//!
//! The device a request resolves is resolved for the person at the browser
//! when the request begins, and holds for the session only while that
//! person is still the one at its browser, or, while nobody is signed in,
//! the one a login in progress names: a person who begins a new login on
//! their own session keeps their device for it, as a guest's request does.
//! A device resolved for nobody (the request began as a guest's, or inside
//! a login, and the resolver knew the device by its token alone) holds for
//! whoever signs in.
//!
//! One function judges, from the row alone and at any moment, rather than a
//! clear at each transition that changes who the session is: those
//! transitions are many and ordered (the start of an impersonation sets the
//! target and then the administrator), and a rule spread over them holds
//! only while nobody adds one.

use super::SessionData;
use crate::authn::ids::{DeviceId, UserId};
use crate::device_key::SessionKeyBinding;

impl SessionData {
    /// The binding, when it is in force for the session as it stands
    /// ([`SessionKeyBinding::in_force_for`]): what every reader that asks
    /// whether the session is bound reads. `None` for a session that is not
    /// bound, and for one whose binding was made for another person than
    /// the one at its browser now.
    pub fn key_binding_in_force(&self) -> Option<&SessionKeyBinding> {
        self.key_binding
            .as_ref()
            .filter(|binding| binding.in_force_for(&self.auth_state))
    }

    /// Remove a binding that is not in force. Says whether it removed one.
    /// Only `key_binding` changes: the request's proven key (`device_key`)
    /// and flag (`key_proven`) are the request's own answers, never stored.
    pub(crate) fn drop_binding_not_in_force(&mut self) -> bool {
        let stale = self.key_binding.is_some() && self.key_binding_in_force().is_none();
        if stale {
            self.key_binding = None;
        }
        stale
    }

    /// The device this session names, while it holds: it was resolved for
    /// `resolved_for` and holds while that person is the one at the
    /// session's browser (the administrator of an impersonation, else the
    /// signed-in user), or, while nobody is signed in, the user a login in
    /// progress or another pending state names. A device resolved for
    /// nobody (the request began as a guest's, or inside a login, and the
    /// resolver knew the device by its token alone) holds for whoever signs
    /// in, which is how a login takes the browser's device as the person's
    /// own.
    ///
    /// The second reading keeps the order of the two: a device resolved for
    /// a person holds wherever one resolved for nobody would, as long as
    /// the session names that person and nobody else. A person who begins a
    /// new login on their own session keeps their device for it, the lockout
    /// exemption of their own device included; a login of anyone else does
    /// not take it, and a guest's state names nobody.
    pub(crate) fn device_in_force(&self, resolved_for: Option<&UserId>) -> Option<DeviceId> {
        let Some(person) = resolved_for else {
            return self.device_id;
        };
        let named = self
            .auth_state
            .person_at_browser()
            .or_else(|| self.auth_state.pending_user_id().copied());
        self.device_id.filter(|_| named.as_ref() == Some(person))
    }

    /// Remove a device id that does not hold. Says whether it removed one.
    /// Only `device_id` changes: the request's own answers about the device
    /// (`device_proven`, `device_key`, `key_proven`) are read beside it and
    /// are never stored.
    pub(crate) fn drop_device_not_in_force(&mut self, resolved_for: Option<&UserId>) -> bool {
        let stale = self.device_id.is_some() && self.device_in_force(resolved_for).is_none();
        if stale {
            self.device_id = None;
        }
        stale
    }
}

#[cfg(test)]
mod tests;
