use std::task::Context;
use crate::codec::{PacketDecode, PacketEncode};
use crate::codes::msg;
use crate::error::{Result, Error};
use super::negotiate;
use super::auth_method::AuthMethod;
use super::client_event::{ClientEvent, AuthBanner};
use super::client_state::{self, ClientState};
use super::pump::Pump;
use super::recv::{self, ResultRecvState};

/// Message sent by the server when authentication attempt fails.
///
/// This corresponds to `SSH_MSG_USERAUTH_FAILURE` (RFC 4252, section 5.1). Note that this may
/// actually represent a [partial success][Self::partial_success].
#[derive(Debug, Clone)]
pub struct AuthFailure {
    /// Authentication methods that may productively continue the authentication.
    ///
    /// Note that the server must not list the `"none"` method here, even if it is supported.
    pub methods_can_continue: Vec<String>,

    /// True if the authentication request was successful, but the authentication should continue.
    ///
    /// For example, this might be used if the server requires that you pass multiple
    /// authentications before continuing.
    pub partial_success: bool,
}

#[derive(Default)]
pub(super) struct AuthState {
    service_requested: bool,
    service_accepted: bool,
    method: Option<Box<dyn AuthMethod + Send>>,
    success: bool,
}

pub(super) fn init_auth() -> AuthState {
    AuthState::default()
}

pub(super) fn start_method(st: &mut ClientState, method: Box<dyn AuthMethod + Send>) -> Result<()> {
    if st.auth_st.method.is_none() {
        st.auth_st.method = Some(method);
        client_state::wakeup_client(st);
        Ok(())
    } else {
        Err(Error::AuthPending)
    }
}

pub(super) fn pump_auth(st: &mut ClientState, _cx: &mut Context) -> Result<Pump> {
    if !st.auth_st.service_requested && negotiate::is_ready(st) {
        send_service_request(st)?;
        st.auth_st.service_requested = true;
        return Ok(Pump::Progress)
    }

    if st.auth_st.service_accepted && st.auth_st.method.is_some() {
        if st.auth_st.success {
            st.auth_st.method.as_mut().unwrap().recv_success()?;
        }

        if negotiate::is_ready(st) {
            let session_id = st.session_id.as_ref().unwrap();
            if let Some(payload) = st.auth_st.method.as_mut().unwrap().send_packet(session_id)? {
                st.codec.send_pipe.feed_packet(&payload)?;
                return Ok(Pump::Progress)
            }
        }

        pump_ready!(st.auth_st.method.as_mut().unwrap().poll())?;
        st.auth_st.method = None;
        return Ok(Pump::Progress)
    }

    Ok(Pump::Pending)
}

fn send_service_request(st: &mut ClientState) -> Result<()> {
    let mut payload = PacketEncode::new();
    payload.put_u8(msg::SERVICE_REQUEST);
    payload.put_str("ssh-userauth");
    st.codec.send_pipe.feed_packet(&payload.finish())?;
    log::debug!("sending SSH_MSG_SERVICE_REQUEST for 'ssh-userauth'");
    Ok(())
}

pub(super) fn recv_service_accept(st: &mut ClientState) -> ResultRecvState {
    log::debug!("received SSH_MSG_SERVICE_ACCEPT for 'ssh-userauth'");
    st.auth_st.service_accepted = true;
    Ok(None)
}

pub(super) fn recv_auth_packet(
    st: &mut ClientState,
    msg_id: u8,
    payload: &mut PacketDecode,
) -> ResultRecvState {
    match msg_id {
        msg::USERAUTH_FAILURE => recv_auth_failure(st, payload),
        msg::USERAUTH_SUCCESS => recv_auth_success(st, payload),
        msg::USERAUTH_BANNER => recv_auth_banner(st, payload),
        _ => Err(Error::PacketNotImplemented(msg_id)),
    }
}

pub(super) fn recv_auth_method_packet(
    st: &mut ClientState,
    msg_id: u8,
    payload: &mut PacketDecode,
) -> ResultRecvState {
    if let Some(method) = st.auth_st.method.as_mut() {
        method.recv_packet(msg_id, payload)?;
        Ok(None)
    } else {
        Err(Error::PacketNotImplemented(msg_id))
    }
}

fn recv_auth_failure(st: &mut ClientState, payload: &mut PacketDecode) -> ResultRecvState {
    let failure = AuthFailure {
        methods_can_continue: payload.get_name_list()?,
        partial_success: payload.get_bool()?,
    };
    log::debug!("received SSH_MSG_USERAUTH_FAILURE: {:?}", failure);

    if let Some(method) = st.auth_st.method.as_mut() {
        method.recv_failure(failure)?;
        Ok(None)
    } else {
        Err(Error::Protocol("received unexpected SSH_MSG_USERAUTH_FAILURE"))
    }
}

fn recv_auth_success(st: &mut ClientState, _payload: &mut PacketDecode) -> ResultRecvState {
    st.auth_st.success = true;
    log::debug!("received SSH_MSG_USERAUTH_SUCCESS");
    Ok(None)
}

fn recv_auth_banner(_st: &mut ClientState, payload: &mut PacketDecode) -> ResultRecvState {
    let banner = AuthBanner {
        message: payload.get_string()?,
        message_lang: payload.get_string()?,
    };
    recv::send_event(ClientEvent::AuthBanner(banner))
}

pub(super) fn is_authenticated(st: &ClientState) -> bool {
    st.auth_st.success
}
