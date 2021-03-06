use anyhow::{Result, Context as _, bail};
use bytes::BytesMut;
use enclose::enclose;
use futures::future::{FutureExt as _, FusedFuture as _};
use regex::Regex;
use rustix::termios;
use std::collections::HashSet;
use std::{env, fs};
use std::future::Future;
use std::os::unix::io::AsRawFd as _;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::ExitCode;
use std::task::{Context, Poll};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

fn main() -> ExitCode {
    env_logger::init();
    match run_main() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("ssh: {:?}", err);
            ExitCode::FAILURE
        },
    }
}

fn run_main() -> Result<ExitCode> {
    let matches = clap::Command::new("client")
        .arg(clap::Arg::new("private-key").short('i')
            .takes_value(true)
            .action(clap::ArgAction::Append)
            .value_parser(clap::value_parser!(PathBuf))
            .value_hint(clap::ValueHint::FilePath)
            .value_name("key-file"))
        .arg(clap::Arg::new("port").short('p')
            .takes_value(true)
            .value_parser(clap::value_parser!(u16))
            .value_name("port"))
        .arg(clap::Arg::new("username").short('l')
            .takes_value(true)
            .value_name("login"))
        .arg(clap::Arg::new("destination")
            .required(true)
            .takes_value(true)
            .value_name("destination"))
        .arg(clap::Arg::new("command")
            .takes_value(true)
            .value_name("command"))
        .arg(clap::Arg::new("want-tty").short('t')
            .action(clap::ArgAction::SetTrue))
        .get_matches();

    let mut destination = Destination::default();
    if let Some(dest) = matches.get_one::<String>("destination") {
        destination = parse_destination(&dest)?;
    }
    destination.port = matches.get_one::<u16>("port").or(destination.port.as_ref()).cloned();
    destination.username = matches.get_one::<String>("username").or(destination.username.as_ref()).cloned();

    let keys = matches.get_many::<PathBuf>("private-key")
        .into_iter().flatten()
        .map(|path| read_key(path))
        .collect::<Result<Vec<_>>>()?;

    let command = matches.get_one::<String>("command").cloned();
    let want_tty = *matches.get_one::<bool>("want-tty").unwrap() || command.is_none();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all().build()?;
    let exit_code = runtime.block_on(run_client(destination, keys, command, want_tty))?;
    runtime.shutdown_background();
    Ok(exit_code)
}

#[derive(Debug, Default)]
struct Destination {
    host: Option<String>,
    port: Option<u16>,
    username: Option<String>,
}

fn parse_destination(dest: &str) -> Result<Destination> {
    let re = Regex::new(r"(?x)
        ^
        (ssh://)?
        ((?P<username>\w+)@)?
        (?P<host>[[:alnum:].]+)
        (:(?P<port>[[:digit:]]+))?
        $
    ").unwrap();
    let captures = re.captures(dest)
        .context("invalid format of `destination`, should be [user@]host[:port]")?;

    let host = captures.name("host").map(|x| x.as_str().into());
    let port = captures.name("port").map(|x| x.as_str().parse()).transpose()
        .context("invalid port number in `destination`")?;
    let username = captures.name("username").map(|x| x.as_str().into());
    Ok(Destination { host, port, username })
}

struct Key {
    path: PathBuf,
    data: Vec<u8>,
    decoded: makiko::keys::OpensshKeypairNopass,
}

fn read_key(path: &Path) -> Result<Key> {
    let data = fs::read(&path)
        .context(format!("could not read file {:?} with private key", path))?;
    let decoded = makiko::keys::decode_openssh_pem_keypair_nopass(&data)
        .context(format!("could not decode keypair from file {:?}", path))?;
    Ok(Key { path: path.into(), data, decoded })
}

async fn run_client(
    destination: Destination,
    keys: Vec<Key>,
    command: Option<String>,
    want_tty: bool,
) -> Result<ExitCode> {
    let host = destination.host
        .context("please specify the host to connect to")?;
    let username = destination.username
        .context("please specify the username to login with")?;
    let port = destination.port.unwrap_or(22);
    let config = makiko::ClientConfig::default_compatible_less_secure();

    log::info!("connecting to host {:?}, port {}", host, port);
    let socket = tokio::net::TcpStream::connect((host, port)).await
        .context("could not open TCP connection to the server")?;
    log::info!("successfully connected");

    let (client, mut client_rx, client_fut) = makiko::Client::open(socket, config)?;
    let client_task = tokio::task::spawn(client_fut);

    let event_task = tokio::task::spawn(enclose!{(client) async move {
        while let Some(event) = client_rx.recv().await {
            if let makiko::ClientEvent::ServerPubkey(pubkey, accept_tx) = event {
                verify_pubkey(&client, pubkey, accept_tx).await?;
            }
        }
        Result::<()>::Ok(())
    }});

    let interact_task = tokio::task::spawn(enclose!{(client) async move {
        authenticate(&client, username, keys).await
            .context("could not authenticate")?;
        log::info!("successfully authenticated");

        let config = makiko::ChannelConfig::default();
        let (session, session_rx) = client.open_session(config).await?;
        let exit_code = interact(session, session_rx, command, want_tty).await?;
        client.disconnect(makiko::DisconnectError::by_app())?;
        Result::<ExitCode>::Ok(exit_code)
    }});

    let mut client_fut = AbortOnDrop(client_task).map(|res| res.expect("client task panicked")).fuse();
    let mut event_fut = AbortOnDrop(event_task).map(|res| res.expect("event task panicked")).fuse();
    let mut interact_fut = AbortOnDrop(interact_task).map(|res| res.expect("interact task panicked")).fuse();

    let mut exit_code = None;
    loop {
        if client_fut.is_terminated() && exit_code.is_some() {
            return Ok(exit_code.unwrap())
        }

        tokio::select!{
            res = &mut client_fut => res?,
            res = &mut event_fut => res?,
            res = &mut interact_fut => exit_code = Some(res?),
        };
    }
}

async fn verify_pubkey(
    client: &makiko::Client,
    pubkey: makiko::Pubkey,
    accept_tx: makiko::AcceptPubkeySender,
) -> Result<()> {
    log::info!("verifying server pubkey: {}", pubkey);
    let prompt = format!("ssh: server pubkey fingerprint {}\nssh: do you want to connect?",
        pubkey.fingerprint());
    if ask_yes_no(&prompt).await? {
        accept_tx.accept();
    } else {
        client.disconnect(makiko::DisconnectError {
            reason_code: makiko::codes::disconnect::HOST_KEY_NOT_VERIFIABLE,
            description: "user did not accept the host public key".into(),
            description_lang: "".into(),
        })?;
    }
    Ok(())
}

async fn authenticate(client: &makiko::Client, username: String, keys: Vec<Key>) -> Result<()> {
    struct AuthCtx<'c> {
        client: &'c makiko::Client,
        username: String,
        methods: HashSet<String>,
        pubkey_algo_names: Option<HashSet<String>>,
    }

    fn update_methods(ctx: &mut AuthCtx, failure: makiko::AuthFailure) {
        log::info!("authentication methods that can continue: {:?}", failure.methods_can_continue);
        ctx.methods = failure.methods_can_continue.into_iter().collect();
    }

    fn update_pubkey_algo_names(ctx: &mut AuthCtx) -> Result<()> {
        ctx.pubkey_algo_names = ctx.client.auth_pubkey_algo_names()?
            .map(|names| names.into_iter().collect::<HashSet<_>>());
        if let Some(names) = ctx.pubkey_algo_names.as_ref() {
            log::info!("server supports these public key algorithms: {:?}", names);
        }
        Ok(())
    }

    async fn try_auth_none(ctx: &mut AuthCtx<'_>) -> Result<bool> {
        log::info!("trying 'none' authentication");
        match ctx.client.auth_none(ctx.username.clone()).await? {
            makiko::AuthNoneResult::Success => return Ok(true),
            makiko::AuthNoneResult::Failure(failure) => update_methods(ctx, failure),
        }
        Ok(false)
    }

    async fn try_auth_key(ctx: &mut AuthCtx<'_>, key: &Key) -> Result<bool> {
        if !ctx.methods.contains("publickey") {
            return Ok(false)
        }

        let mut password = None;
        for algo in key.decoded.pubkey.algos_compatible_less_secure().iter() {
            if let Some(names) = ctx.pubkey_algo_names.as_ref() {
                if !names.contains(algo.name) {
                    continue
                }
            }

            if try_auth_key_algo(ctx, &key, algo, &mut password).await? {
                return Ok(true)
            }
        }
        Ok(false)
    }

    async fn try_auth_key_algo(
        ctx: &mut AuthCtx<'_>,
        key: &Key,
        algo: &'static makiko::PubkeyAlgo,
        password: &mut Option<String>,
    ) -> Result<bool> {
        log::info!("checking 'publickey' authentication with key {}, algorithm {:?}",
            key.path.display(), algo.name);
        if !ctx.client.check_pubkey(ctx.username.clone(), &key.decoded.pubkey, algo).await? {
            return Ok(false)
        }

        let privkey = match key.decoded.privkey {
            Some(ref privkey) => privkey.clone(),
            None => decode_privkey(key, password).await?,
        };

        log::info!("trying 'publickey' authentication with key {}, algorithm {:?}",
            key.path.display(), algo.name);
        match ctx.client.auth_pubkey(ctx.username.clone(), privkey, algo).await? {
            makiko::AuthPubkeyResult::Success => return Ok(true),
            makiko::AuthPubkeyResult::Failure(failure) => update_methods(ctx, failure),
        }
        Ok(false)
    }

    async fn decode_privkey(key: &Key, password: &mut Option<String>) -> Result<makiko::Privkey> {
        loop {
            let prompt = format!("ssh: password for key {}", key.path.display());
            if password.is_none() {
                *password = Some(ask_for_password(&prompt).await?);
            }
            let password = password.as_ref().unwrap().as_bytes();
            match makiko::keys::decode_openssh_pem_keypair(&key.data, password) {
                Ok(decoded) => return Ok(decoded.privkey),
                Err(makiko::Error::BadKeyPassphrase) => continue,
                Err(err) => return Err(err.into()),
            }
        }
    }

    async fn try_auth_password(ctx: &mut AuthCtx<'_>) -> Result<bool> {
        if !ctx.methods.contains("password") {
            return Ok(false)
        }

        log::info!("trying 'password' authentication");
        let prompt = format!("ssh: password for user {:?}", ctx.username);
        let password = ask_for_password(&prompt).await?;
        match ctx.client.auth_password(ctx.username.clone(), password).await? {
            makiko::AuthPasswordResult::Success => return Ok(true),
            makiko::AuthPasswordResult::ChangePassword(prompt) =>
                bail!("server wants you to change your password: {:?}", prompt.prompt),
            makiko::AuthPasswordResult::Failure(failure) => update_methods(ctx, failure),
        }
        Ok(false)
    }

    let mut ctx = AuthCtx {
        client, username,
        methods: HashSet::new(),
        pubkey_algo_names: None,
    };

    if try_auth_none(&mut ctx).await? { return Ok(()) }
    update_pubkey_algo_names(&mut ctx)?;
    for key in keys.iter() {
        if try_auth_key(&mut ctx, key).await? { return Ok(()) }
    }
    if try_auth_password(&mut ctx).await? { return Ok(()) }

    bail!("no authentication method succeeded")
}

async fn interact(
    session: makiko::Session,
    mut session_rx: makiko::SessionReceiver,
    command: Option<String>,
    want_tty: bool,
) -> Result<ExitCode> {
    let mut pty_req = None;
    let mut orig_tio = None;
    if want_tty && termios::isatty(std::io::stdin()) {
        pty_req = Some(get_pty_request()?);
        orig_tio = Some(enter_raw_mode()?);
    }

    let recv_task = tokio::task::spawn(async move {
        let mut stdout = tokio::io::stdout();
        let mut stderr = tokio::io::stderr();

        while let Some(event) = session_rx.recv().await? {
            match event {
                makiko::SessionEvent::StdoutData(data) => {
                    stdout.write_all(&data).await?;
                    stdout.flush().await?;
                },
                makiko::SessionEvent::StderrData(data) => {
                    stderr.write_all(&data).await?;
                    stderr.flush().await?;
                },
                makiko::SessionEvent::ExitStatus(status) => {
                    log::info!("received exit status {}", status);
                    return Ok(ExitCode::from(status as u8))
                },
                makiko::SessionEvent::ExitSignal(signal) => {
                    log::info!("received exit signal {:?}", signal.signal_name);
                    let msg = format!("ssh: remote process exited with signal {:?}: {:?}\n",
                        signal.signal_name, signal.message);
                    stderr.write_all(msg.as_bytes()).await?;
                    return Ok(ExitCode::from(255))
                },
                _ => {},
            }
        }
        bail!("session terminated before remote process exited")
    });

    let send_task = tokio::task::spawn(enclose!{(session) async move {
        if let Some(pty_req) = pty_req.as_ref() {
            session.request_pty(&pty_req)?.want_reply().await?;
        }

        if let Some(command) = command {
            session.exec(command.as_bytes())?.want_reply().await?;
        } else {
            session.shell()?.want_reply().await?;
        }

        let mut stdin = tokio::io::stdin();
        let mut stdin_buf = BytesMut::new();
        let mut winch_stream = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())?;
        loop {
            tokio::select!{
                res = stdin.read_buf(&mut stdin_buf) => {
                    if res? > 0 {
                        session.send_stdin(stdin_buf.split().freeze()).await?
                    } else {
                        break
                    }
                },
                Some(()) = winch_stream.recv() => {
                    session.window_change(&get_window_change()?)?;
                },
            }
        }

        session.send_eof().await?;
        Result::<()>::Ok(())
    }});

    let mut recv_fut = AbortOnDrop(recv_task).map(|res| res.expect("receiving task panicked")).fuse();
    let mut send_fut = AbortOnDrop(send_task).map(|res| res.expect("sending task panicked")).fuse();
    loop {
        tokio::select!{
            recv_res = &mut recv_fut => {
                if let Some(tio) = orig_tio {
                    leave_raw_mode(tio);
                }
                return recv_res
            },
            send_res = &mut send_fut => send_res?,
        };
    }
}

#[derive(Debug)]
pub struct AbortOnDrop<T>(pub tokio::task::JoinHandle<T>);

impl<T> Future for AbortOnDrop<T> {
    type Output = Result<T, tokio::task::JoinError>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.get_mut().0).poll(cx)
    }
}

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn ask_yes_no(prompt: &str) -> Result<bool> {
    let mut stdout = tokio::io::stdout();
    stdout.write_all(format!("{} [y/N]: ", prompt).as_bytes()).await?;
    stdout.flush().await?;

    let mut stdin = tokio::io::stdin();
    let mut yes = false;
    loop {
        let c = stdin.read_u8().await?;
        if c == b'\r' || c == b'\n' {
            break
        } else if c.is_ascii_whitespace() {
            continue
        } else if c == b'y' || c == b'Y' {
            yes = true;
        } else {
            yes = false;
        }
    }

    Ok(yes)
}

async fn ask_for_password(prompt: &str) -> Result<String> {
    let mut stdout = tokio::io::stdout();
    stdout.write_all(format!("{}: ", prompt).as_bytes()).await?;
    stdout.flush().await?;

    let mut stdin = tokio::io::stdin();
    let stdin_raw = unsafe { rustix::fd::BorrowedFd::borrow_raw(stdin.as_raw_fd()) };
    let orig_tio = termios::tcgetattr(stdin_raw)?;

    let mut tio = orig_tio;
    tio.c_lflag &= !termios::ECHO;
    termios::tcsetattr(stdin_raw, termios::OptionalActions::Drain, &tio)?;

    let mut password = Vec::new();
    loop {
        let c = stdin.read_u8().await?;
        if password.is_empty() && c.is_ascii_whitespace() {
            continue
        } else if c == b'\r' || c == b'\n' {
            break
        } else {
            password.push(c);
        }
    }
    stdout.write_u8(b'\n').await?;

    termios::tcsetattr(stdin_raw, termios::OptionalActions::Drain, &orig_tio)?;
    Ok(std::str::from_utf8(&password)?.into())
}

fn enter_raw_mode() -> Result<termios::Termios> {
    // this code is shamelessly copied from OpenSSH

    let stdin = tokio::io::stdin();
    let stdin_raw = unsafe { rustix::fd::BorrowedFd::borrow_raw(stdin.as_raw_fd()) };

    let orig_tio = termios::tcgetattr(stdin_raw)?;
    let mut tio = orig_tio;

	tio.c_iflag |= termios::IGNPAR;
	tio.c_iflag &= !(termios::ISTRIP | termios::INLCR | termios::IGNCR | termios::ICRNL 
        | termios::IXON | termios::IXANY | termios::IXOFF | termios::IUCLC);
	tio.c_lflag &= !(termios::ISIG | termios::ICANON | termios::ECHO | termios::ECHOE 
        | termios::ECHOK | termios::ECHONL | termios::IEXTEN);
	tio.c_oflag &= !termios::OPOST;
	tio.c_cc[termios::VMIN] = 1;
	tio.c_cc[termios::VTIME] = 0;

    log::debug!("entering terminal raw mode");
    termios::tcsetattr(stdin_raw, termios::OptionalActions::Drain, &tio)?;
    Ok(orig_tio)
}

fn leave_raw_mode(tio: termios::Termios) {
    let stdin = tokio::io::stdin();
    let stdin_raw = unsafe { rustix::fd::BorrowedFd::borrow_raw(stdin.as_raw_fd()) };
    let _ = termios::tcsetattr(stdin_raw, termios::OptionalActions::Drain, &tio);
    log::debug!("left terminal raw mode");
}

fn get_window_change() -> Result<makiko::WindowChange> {
    let winsize = termios::tcgetwinsize(std::io::stdin())?;
    Ok(makiko::WindowChange {
        width: winsize.ws_col as u32,
        height: winsize.ws_row as u32,
        width_px: winsize.ws_xpixel as u32,
        height_px: winsize.ws_ypixel as u32,
    })
}

fn get_pty_request() -> Result<makiko::PtyRequest> {
    // this code is shamelessly copied from OpenSSH

    let mut req = makiko::PtyRequest::default();
    req.term = env::var("TERM").unwrap_or(String::new());

    let stdin = tokio::io::stdin();
    let stdin_raw = unsafe { rustix::fd::BorrowedFd::borrow_raw(stdin.as_raw_fd()) };
    let winsize = termios::tcgetwinsize(stdin_raw)?;
    req.width = winsize.ws_col as u32;
    req.height = winsize.ws_row as u32;
    req.width_px = winsize.ws_xpixel as u32;
    req.height_px = winsize.ws_ypixel as u32;

    let tio = termios::tcgetattr(stdin_raw)?;

    macro_rules! tty_char {
        ($name:ident, $op:ident) => {
            let value = tio.c_cc[termios::$name];
            let value = if value == 0 { 255 } else { value as u32 };
            req.modes.add(makiko::codes::terminal_mode::$op, value);
        };
        ($name:ident) => {
            tty_char!($name, $name)
        };
    }

    macro_rules! tty_mode {
        ($name:ident, $field:ident, $op:ident) => {
            let value = (tio.$field & termios::$name) != 0;
            let value = value as u32;
            req.modes.add(makiko::codes::terminal_mode::$op, value);
        };
        ($name:ident, $field:ident) => {
            tty_mode!($name, $field, $name)
        };
    }

    tty_char!(VINTR);
    tty_char!(VQUIT);
    tty_char!(VERASE);
    tty_char!(VKILL);
    tty_char!(VEOF);
    tty_char!(VEOL);
    tty_char!(VEOL2);
    tty_char!(VSTART);
    tty_char!(VSTOP);
    tty_char!(VSUSP);
    tty_char!(VREPRINT);
    tty_char!(VWERASE);
    tty_char!(VLNEXT);
    tty_char!(VDISCARD);

    tty_mode!(IGNPAR, c_iflag);
    tty_mode!(PARMRK, c_iflag);
    tty_mode!(INPCK, c_iflag);
    tty_mode!(ISTRIP, c_iflag);
    tty_mode!(INLCR, c_iflag);
    tty_mode!(IGNCR, c_iflag);
    tty_mode!(ICRNL, c_iflag);
    tty_mode!(IUCLC, c_iflag);
    tty_mode!(IXON, c_iflag);
    tty_mode!(IXANY, c_iflag);
    tty_mode!(IXOFF, c_iflag);
    tty_mode!(IMAXBEL, c_iflag);
    tty_mode!(IUTF8, c_iflag);

    tty_mode!(ISIG, c_lflag);
    tty_mode!(ICANON, c_lflag);
    tty_mode!(XCASE, c_lflag);
    tty_mode!(ECHO, c_lflag);
    tty_mode!(ECHOE, c_lflag);
    tty_mode!(ECHOK, c_lflag);
    tty_mode!(ECHONL, c_lflag);
    tty_mode!(NOFLSH, c_lflag);
    tty_mode!(TOSTOP, c_lflag);
    tty_mode!(IEXTEN, c_lflag);
    tty_mode!(ECHOCTL, c_lflag);
    tty_mode!(ECHOKE, c_lflag);
    tty_mode!(PENDIN, c_lflag);

    tty_mode!(OPOST, c_oflag);
    tty_mode!(OLCUC, c_oflag);
    tty_mode!(ONLCR, c_oflag);
    tty_mode!(OCRNL, c_oflag);
    tty_mode!(ONOCR, c_oflag);
    tty_mode!(ONLRET, c_oflag);

    tty_mode!(CS7, c_cflag);
    tty_mode!(CS8, c_cflag);
    tty_mode!(PARENB, c_cflag);
    tty_mode!(PARODD, c_cflag);

    Ok(req)
}
