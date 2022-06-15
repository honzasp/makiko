//! Various codes from the SSH protocol.
#![allow(dead_code)]
#![allow(missing_docs)]

pub(crate) mod msg {
    pub const DISCONNECT: u8 = 1;
    pub const IGNORE: u8 = 2;
    pub const UNIMPLEMENTED: u8 = 3;
    pub const DEBUG: u8 = 4;
    pub const SERVICE_REQUEST: u8 = 5;
    pub const SERVICE_ACCEPT: u8 = 6;
    pub const KEXINIT: u8 = 20;
    pub const NEWKEYS: u8 = 21;
    pub const USERAUTH_REQUEST: u8 = 50;
    pub const USERAUTH_FAILURE: u8 = 51;
    pub const USERAUTH_SUCCESS: u8 = 52;
    pub const USERAUTH_BANNER: u8 = 53;
    pub const GLOBAL_REQUEST: u8 = 80;
    pub const REQUEST_SUCCESS: u8 = 81;
    pub const REQUEST_FAILURE: u8 = 82;
    pub const CHANNEL_OPEN: u8 = 90;
    pub const CHANNEL_OPEN_CONFIRMATION: u8 = 91;
    pub const CHANNEL_OPEN_FAILURE: u8 = 92;
    pub const CHANNEL_WINDOW_ADJUST: u8 = 93;
    pub const CHANNEL_DATA: u8 = 94;
    pub const CHANNEL_EXTENDED_DATA: u8 = 95;
    pub const CHANNEL_EOF: u8 = 96;
    pub const CHANNEL_CLOSE: u8 = 97;
    pub const CHANNEL_REQUEST: u8 = 98;
    pub const CHANNEL_SUCCESS: u8 = 99;
    pub const CHANNEL_FAILURE: u8 = 100;

    pub const KEX_ECDH_INIT: u8 = 30;
    pub const KEX_ECDH_REPLY: u8 = 31;

    pub const USERAUTH_PASSWD_CHANGEREQ: u8 = 60;
}

/// Reason codes for [`DisconnectError`][crate::DisconnectError].
pub mod disconnect {
    pub const HOST_NOT_ALLOWED_TO_CONNECT: u32 = 1;
    pub const PROTOCOL_ERROR: u32 = 2;
    pub const KEY_EXCHANGE_FAILED: u32 = 3;
    pub const RESERVED: u32 = 4;
    pub const MAC_ERROR: u32 = 5;
    pub const COMPRESSION_ERROR: u32 = 6;
    pub const SERVICE_NOT_AVAILABLE: u32 = 7;
    pub const PROTOCOL_VERSION_NOT_SUPPORTED: u32 = 8;
    pub const HOST_KEY_NOT_VERIFIABLE: u32 = 9;
    pub const CONNECTION_LOST: u32 = 10;
    pub const BY_APPLICATION: u32 = 11;
    pub const TOO_MANY_CONNECTIONS: u32 = 12;
    pub const AUTH_CANCELLED_BY_USER: u32 = 13;
    pub const NO_MORE_AUTH_METHODS_AVAILABLE: u32 = 14;
    pub const ILLEGAL_USER_NAME: u32 = 15;

    /// Convert a reason code to a string.
    pub const fn to_str(code: u32) -> Option<&'static str> {
        Some(match code {
            HOST_NOT_ALLOWED_TO_CONNECT => "host not allowed to connect",
            PROTOCOL_ERROR => "protocol error",
            KEY_EXCHANGE_FAILED => "key exchange failed",
            RESERVED => "reserved",
            MAC_ERROR => "mac error",
            COMPRESSION_ERROR => "compression error",
            SERVICE_NOT_AVAILABLE => "service not available",
            PROTOCOL_VERSION_NOT_SUPPORTED => "protocol version not supported",
            HOST_KEY_NOT_VERIFIABLE => "host key not verifiable",
            CONNECTION_LOST => "connection lost",
            BY_APPLICATION => "by application",
            TOO_MANY_CONNECTIONS => "too many connections",
            AUTH_CANCELLED_BY_USER => "auth cancelled by user",
            NO_MORE_AUTH_METHODS_AVAILABLE => "no more auth methods available",
            ILLEGAL_USER_NAME => "illegal user name",
            _ => return None,
        })
    }
}

/// Reason codes for [`ChannelOpenError`][crate::ChannelOpenError].
pub mod open {
    pub const ADMINISTRATIVELY_PROHIBITED: u32 = 1;
    pub const CONNECT_FAILED: u32 = 2;
    pub const UNKNOWN_CHANNEL_TYPE: u32 = 3;
    pub const RESOURCE_SHORTAGE: u32 = 4;

    /// Convert a reason code to a string.
    pub const fn to_str(code: u32) -> Option<&'static str> {
        Some(match code {
            ADMINISTRATIVELY_PROHIBITED => "administratively prohibited",
            CONNECT_FAILED => "connect failed",
            UNKNOWN_CHANNEL_TYPE => "unknown channel type",
            RESOURCE_SHORTAGE => "resource shortage",
            _ => return None,
        })
    }
}

/// Signal codes for [`Session::signal()`][crate::Session::signal()] and
/// [`ExitSignal`][crate::ExitSignal].
///
/// The constants are the same as the codes, so for example [`ABRT`][signal::ABRT] is `"ABRT"`.
pub mod signal {
    pub static ABRT: &'static str = "ABRT";
    pub static ALRM: &'static str = "ALRM";
    pub static FPE: &'static str = "FPE";
    pub static HUP: &'static str = "HUP";
    pub static ILL: &'static str = "ILL";
    pub static INT: &'static str = "INT";
    pub static KILL: &'static str = "KILL";
    pub static PIPE: &'static str = "PIPE";
    pub static QUIT: &'static str = "QUIT";
    pub static SEGV: &'static str = "SEGV";
    pub static TERM: &'static str = "TERM";
    pub static USR1: &'static str = "USR1";
    pub static USR2: &'static str = "USR2";
}
