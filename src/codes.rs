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
    pub const EXT_INFO: u8 = 7;
    pub const NEWCOMPRESS: u8 = 8;
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

    pub const KEXDH_INIT: u8 = 30;
    pub const KEXDH_REPLY: u8 = 31;

    pub const USERAUTH_PASSWD_CHANGEREQ: u8 = 60;
    pub const USERAUTH_PK_OK: u8 = 60;
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
    pub static ABRT: &str = "ABRT";
    pub static ALRM: &str = "ALRM";
    pub static FPE: &str = "FPE";
    pub static HUP: &str = "HUP";
    pub static ILL: &str = "ILL";
    pub static INT: &str = "INT";
    pub static KILL: &str = "KILL";
    pub static PIPE: &str = "PIPE";
    pub static QUIT: &str = "QUIT";
    pub static SEGV: &str = "SEGV";
    pub static TERM: &str = "TERM";
    pub static USR1: &str = "USR1";
    pub static USR2: &str = "USR2";
}

/// Terminal mode opcodes for [`PtyTerminalModes`][crate::PtyTerminalModes].
///
/// For more information, please consult RFC 4254, section 8.
pub mod terminal_mode {
    /// Indicates end of options.
    pub const TTY_OP_END: u8 = 0;

    /// Interrupt character; 255 if none. Similarly for the other characters.  Not all of these
    /// characters are supported on all systems.
    pub const VINTR: u8 = 1;
    /// The quit character (sends SIGQUIT signal on POSIX systems).
    pub const VQUIT: u8 = 2;
    /// Erase the character to left of the cursor.
    pub const VERASE: u8 = 3;
    /// Kill the current input line.
    pub const VKILL: u8 = 4;
    /// End-of-file character (sends EOF from the terminal).
    pub const VEOF: u8 = 5;
    /// End-of-line character in addition to carriage return and/or linefeed.
    pub const VEOL: u8 = 6;
    /// Additional end-of-line character.
    pub const VEOL2: u8 = 7;
    /// Continues paused output (normally control-Q).
    pub const VSTART: u8 = 8;
    /// Pauses output (normally control-S).
    pub const VSTOP: u8 = 9;
    /// Suspends the current program.
    pub const VSUSP: u8 = 10;
    /// Another suspend character.
    pub const VDSUSP: u8 = 11;
    /// Reprints the current input line.
    pub const VREPRINT: u8 = 12;
    /// Erases a word left of cursor.
    pub const VWERASE: u8 = 13;
    /// Enter the next character typed literally, even if it is a special character
    pub const VLNEXT: u8 = 14;
    /// Character to flush output.
    pub const VFLUSH: u8 = 15;
    /// Switch to a different shell layer.
    pub const VSWTCH: u8 = 16;
    /// Prints system status line (load, command, pid, etc).
    pub const VSTATUS: u8 = 17;
    /// Toggles the flushing of terminal output.
    pub const VDISCARD: u8 = 18;

    /// The ignore parity flag.  The parameter SHOULD be 0 if this flag is FALSE, and 1 if it is
    /// TRUE.
    pub const IGNPAR: u8 = 30;
    /// Mark parity and framing errors.
    pub const PARMRK: u8 = 31;
    /// Enable checking of parity errors.
    pub const INPCK: u8 = 32;
    /// Strip 8th bit off characters.
    pub const ISTRIP: u8 = 33;
    /// Map NL into CR on input.
    pub const INLCR: u8 = 34;
    /// Ignore CR on input.
    pub const IGNCR: u8 = 35;
    /// Map CR to NL on input.
    pub const ICRNL: u8 = 36;
    /// Translate uppercase characters to lowercase.
    pub const IUCLC: u8 = 37;
    /// Enable output flow control.
    pub const IXON: u8 = 38;
    /// Any char will restart after stop.
    pub const IXANY: u8 = 39;
    /// Enable input flow control.
    pub const IXOFF: u8 = 40;
    /// Ring bell on input queue full.
    pub const IMAXBEL: u8 = 41;
    /// Terminal input and output is assumed to be encoded in UTF-8.
    pub const IUTF8: u8 = 42;

    /// Enable signals INTR, QUIT, \[D\]SUSP.
    pub const ISIG: u8 = 50;
    /// Canonicalize input lines.
    pub const ICANON: u8 = 51;
    /// Enable input and output of uppercase characters by preceding their lowercase equivalents
    /// with "\".
    pub const XCASE: u8 = 52;
    /// Enable echoing.
    pub const ECHO: u8 = 53;
    /// Visually erase chars.
    pub const ECHOE: u8 = 54;
    /// Kill character discards current line.
    pub const ECHOK: u8 = 55;
    /// Echo NL even if ECHO is off.
    pub const ECHONL: u8 = 56;
    /// Don't flush after interrupt.
    pub const NOFLSH: u8 = 57;
    /// Stop background jobs from output.
    pub const TOSTOP: u8 = 58;
    /// Enable extensions.
    pub const IEXTEN: u8 = 59;
    /// Echo control characters as ^(Char).
    pub const ECHOCTL: u8 = 60;
    /// Visual erase for line kill.
    pub const ECHOKE: u8 = 61;
    /// Retype pending input.
    pub const PENDIN: u8 = 62;

    /// Enable output processing.
    pub const OPOST: u8 = 70;
    /// Convert lowercase to uppercase.
    pub const OLCUC: u8 = 71;
    /// Map NL to CR-NL.
    pub const ONLCR: u8 = 72;
    /// Translate carriage return to newline (output).
    pub const OCRNL: u8 = 73;
    /// Translate newline to carriage return-newline (output).
    pub const ONOCR: u8 = 74;
    /// Newline performs a carriage return (output).
    pub const ONLRET: u8 = 75;

    /// 7 bit mode.
    pub const CS7: u8 = 90;
    /// 8 bit mode.
    pub const CS8: u8 = 91;
    /// Parity enable.
    pub const PARENB: u8 = 92;
    /// Odd parity, else even.
    pub const PARODD: u8 = 93;

    /// Specifies the input baud rate in bits per second.
    pub const TTY_OP_ISPEED: u8 = 128;
    /// Specifies the output baud rate in bits per second.
    pub const TTY_OP_OSPEED: u8 = 129;
}
