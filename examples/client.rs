use anyhow::{Result, Context as _, bail};
use bytes::BytesMut;
use enclose::enclose;
use futures::ready;
use futures::future::{FutureExt as _, FusedFuture as _, Fuse};
use futures::stream::{StreamExt as _, TryStreamExt as _, FuturesUnordered};
use guard::guard;
use regex::Regex;
use rustix::termios;
use std::collections::{HashMap, HashSet};
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
        .arg(clap::Arg::new("local-tunnel").short('L')
            .takes_value(true)
            .action(clap::ArgAction::Append)
            .value_name("[local-host:]local-port:remote-host:remote-port"))
        .arg(clap::Arg::new("remote-tunnel").short('R')
            .takes_value(true)
            .action(clap::ArgAction::Append)
            .value_name("[remote-host:]remote-port:local-host:local-port"))
        .get_matches();

    let mut destination = Destination::default();
    if let Some(dest) = matches.get_one::<String>("destination") {
        destination = parse_destination(&dest)?;
    }
    destination.port = matches.get_one::<u16>("port").or(destination.port.as_ref()).cloned();
    destination.username = matches.get_one::<String>("username").or(destination.username.as_ref()).cloned();

    let keys = matches.get_many::<PathBuf>("private-key")
        .into_iter().flatten()
        .map(|key| read_key(&key))
        .collect::<Result<Vec<_>>>()?;

    let command = matches.get_one::<String>("command").cloned();
    let want_tty = *matches.get_one::<bool>("want-tty").unwrap() || command.is_none();

    let local_tunnels = matches.get_many::<String>("local-tunnel")
        .into_iter().flatten()
        .map(|spec| parse_tunnel_spec(&spec))
        .collect::<Result<Vec<_>>>()?;
    let remote_tunnels = matches.get_many::<String>("remote-tunnel")
        .into_iter().flatten()
        .map(|spec| parse_tunnel_spec(&spec))
        .collect::<Result<Vec<_>>>()?;

    let opts = Opts { destination, keys, command, want_tty, local_tunnels, remote_tunnels };

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all().build()?;
    let exit_code = runtime.block_on(run_client(opts))?;
    runtime.shutdown_background();
    Ok(exit_code)
}

#[derive(Debug)]
struct Opts {
    destination: Destination,
    keys: Vec<Key>,
    command: Option<String>,
    want_tty: bool,
    local_tunnels: Vec<TunnelSpec>,
    remote_tunnels: Vec<TunnelSpec>,
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
        ((?P<username>\w+) @)?
        (?P<host>[[:alnum:].]+)
        (: (?P<port>[[:digit:]]+))?
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

#[derive(Debug)]
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

#[derive(Debug)]
struct TunnelSpec {
    bind_host: Option<String>,
    bind_port: u16,
    connect_host: String,
    connect_port: u16,
}

fn parse_tunnel_spec(spec: &str) -> Result<TunnelSpec> {
    let re = Regex::new(r"(?x)
        ^
        ((?P<bind_host>[[:alnum:].]+) :)?
        (?P<bind_port>[[:digit:]]+) :
        (?P<connect_host>[[:alnum:].]+) :
        (?P<connect_port>[[:digit:]]+)
        $
    ").unwrap();
    let captures = re.captures(spec)
        .context("invalid format of tunnel spec")?;

    let bind_host = captures.name("bind_host").map(|x| x.as_str().into());
    let bind_port = captures.name("bind_port").unwrap().as_str().parse()
        .context("invalid bind-port in tunnel spec")?;
    let connect_host = captures.name("connect_host").unwrap().as_str().into();
    let connect_port = captures.name("connect_port").unwrap().as_str().parse()
        .context("invalid connect-port in tunnel spec")?;
    Ok(TunnelSpec { bind_host, bind_port, connect_host, connect_port })
}

async fn run_client(opts: Opts) -> Result<ExitCode> {
    let host = opts.destination.host
        .context("please specify the host to connect to")?;
    let username = opts.destination.username
        .context("please specify the username to login with")?;
    let port = opts.destination.port.unwrap_or(22);
    let config = makiko::ClientConfig::default_compatible_less_secure();

    log::info!("connecting to host {:?}, port {}", host, port);
    let socket = tokio::net::TcpStream::connect((host, port)).await
        .context("could not open TCP connection to the server")?;
    log::info!("successfully connected");

    let remote_tunnel_addrs = opts.remote_tunnels.into_iter()
        .map(|spec| {
            let bind_addr = (spec.bind_host.unwrap_or("".into()), spec.bind_port);
            let connect_addr = (spec.connect_host, spec.connect_port);
            (bind_addr, connect_addr)
        })
        .collect::<HashMap<_, _>>();

    let (client, client_rx, client_fut) = makiko::Client::open(socket, config)?;
    let client_task = TaskHandle(tokio::task::spawn(client_fut));

    let event_task = TaskHandle(tokio::task::spawn(
        run_events(client.clone(), client_rx, remote_tunnel_addrs.clone())
    ));

    let interact_task = TaskHandle(tokio::task::spawn(enclose!{(client) async move {
        authenticate(&client, username, opts.keys).await
            .context("could not authenticate")?;
        log::info!("successfully authenticated");

        bind_remote_tunnels(&client, &remote_tunnel_addrs).await?;

        let session_task = TaskHandle(tokio::task::spawn(enclose!{(client) async move {
            run_session(client, opts.command, opts.want_tty).await
        }}));

        let tunnel_tasks = opts.local_tunnels.into_iter().map(enclose!{(client) |spec| {
            TaskHandle(tokio::task::spawn(run_local_tunnel(client.clone(), spec)))
        }}).collect::<FuturesUnordered<_>>();

        let mut session_fut = session_task.fuse();
        let mut tunnels_fut = tunnel_tasks.try_collect().fuse();
        let mut exit_code = ExitCode::SUCCESS;
        while !session_fut.is_terminated() || !tunnels_fut.is_terminated() {
            tokio::select! {
                res = &mut session_fut => exit_code = res?,
                res = &mut tunnels_fut => res?,
            }
        }

        client.disconnect(makiko::DisconnectError::by_app())?;
        Result::<_>::Ok(exit_code)
    }}));

    let mut client_fut = client_task.fuse();
    let mut event_fut = event_task.fuse();
    let mut interact_fut = interact_task.fuse();

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

async fn run_events(
    client: makiko::Client,
    mut client_rx: makiko::ClientReceiver,
    remote_tunnel_addrs: HashMap<(String, u16), (String, u16)>,
) -> Result<()> {
    let mut pubkey_task = Fuse::terminated();
    let mut tunnel_tasks = FuturesUnordered::new();
    loop {
        tokio::select!{
            event = client_rx.recv() => match event? {
                Some(makiko::ClientEvent::ServerPubkey(pubkey, accept_tx)) => {
                    pubkey_task = TaskHandle(tokio::task::spawn(
                        verify_pubkey(client.clone(), pubkey, accept_tx)
                    )).fuse();
                },
                Some(makiko::ClientEvent::Tunnel(accept)) => {
                    let connect_addr = remote_tunnel_addrs.get(&accept.connected_addr);
                    guard!{let Some(connect_addr) = connect_addr else { continue }};
                    tunnel_tasks.push(TaskHandle(tokio::task::spawn(
                        run_remote_tunnel(accept, connect_addr.clone())
                    )));
                },
                Some(_) => continue,
                None => break,
            },
            res = &mut pubkey_task => res?,
            Some(res) = tunnel_tasks.next() => res?,
        };
    }
    Ok(())
}

async fn verify_pubkey(
    client: makiko::Client,
    pubkey: makiko::Pubkey,
    accept_tx: makiko::AcceptPubkey,
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

async fn run_remote_tunnel(accept: makiko::AcceptTunnel, connect_addr: (String, u16)) -> Result<()> {
    match tokio::net::TcpStream::connect(&connect_addr).await {
        Ok(socket) => {
            let config = makiko::ChannelConfig::default();
            let (tunnel, tunnel_rx) = accept.accept(config).await?;
            run_tunnel_socket(tunnel, tunnel_rx, socket).await
        },
        Err(err) => {
            log::warn!("Could not open tunnel to {:?}: {}", connect_addr, err);
            accept.reject(makiko::ChannelOpenError {
                reason_code: makiko::codes::open::CONNECT_FAILED,
                description: format!("Connect attempt failed: {}", err),
                description_lang: "".into(),
            });
            Ok(())
        },
    }
}

async fn bind_remote_tunnels(
    client: &makiko::Client,
    remote_tunnel_addrs: &HashMap<(String, u16), (String, u16)>,
) -> Result<()> {
    for bind_addr in remote_tunnel_addrs.keys() {
        client.bind_tunnel(bind_addr.clone())?.wait().await?;
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

async fn run_session(client: makiko::Client, command: Option<String>, want_tty: bool) -> Result<ExitCode> {
    let config = makiko::ChannelConfig::default();
    let (session, mut session_rx) = client.open_session(config).await?;

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
            session.request_pty(&pty_req)?.wait().await?;
        }

        if let Some(command) = command {
            session.exec(command.as_bytes())?.wait().await?;
        } else {
            session.shell()?.wait().await?;
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

    let mut recv_fut = TaskHandle(recv_task);
    let mut send_fut = TaskHandle(send_task).fuse();
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

async fn run_local_tunnel(client: makiko::Client, spec: TunnelSpec) -> Result<()> {
    let bind_addr = (spec.bind_host.unwrap_or("localhost".into()), spec.bind_port);
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    let mut socket_tasks = FuturesUnordered::new();
    loop {
        tokio::select!{
            res = listener.accept() => {
                let (socket, peer_addr) = res?;

                let config = makiko::ChannelConfig::default();
                let connect_addr = (spec.connect_host.clone(), spec.connect_port);
                let originator_addr = (peer_addr.ip().to_string(), peer_addr.port());
                let (tunnel, tunnel_rx) = client.connect_tunnel(
                    config, connect_addr, originator_addr).await?;

                let task = TaskHandle(tokio::task::spawn(run_tunnel_socket(tunnel, tunnel_rx, socket)));
                socket_tasks.push(task);
            },
            Some(res) = socket_tasks.next() => res?,
        }
    }
}

async fn run_tunnel_socket(
    tunnel: makiko::Tunnel,
    mut tunnel_rx: makiko::TunnelReceiver,
    socket: tokio::net::TcpStream,
) -> Result<()> {
    let (mut socket_read, mut socket_write) = socket.into_split();

    let socket_to_tunnel = TaskHandle(tokio::task::spawn(async move {
        let mut buffer = BytesMut::new();
        while socket_read.read_buf(&mut buffer).await? != 0 {
            tunnel.send_data(buffer.split().freeze()).await?;
        }
        tunnel.send_eof().await?;
        Result::<_>::Ok(())
    }));

    let tunnel_to_socket = TaskHandle(tokio::task::spawn(async move {
        while let Some(event) = tunnel_rx.recv().await? {
            match event {
                makiko::TunnelEvent::Data(mut data) =>
                    socket_write.write_all_buf(&mut data).await?,
                makiko::TunnelEvent::Eof =>
                    break,
                _ => {},
            }
        }
        Result::<_>::Ok(())
    }));

    tokio::try_join!(socket_to_tunnel, tunnel_to_socket)?;
    Ok(())
}

#[derive(Debug)]
pub struct TaskHandle<T>(pub tokio::task::JoinHandle<T>);

impl<T> Future for TaskHandle<T> {
    type Output = T;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match ready!(Pin::new(&mut self.get_mut().0).poll(cx)) {
            Ok(res) => Poll::Ready(res),
            Err(err) if err.is_panic() => std::panic::resume_unwind(err.into_panic()),
            Err(err) => panic!("Task failed: {}", err),
        }
    }
}

impl<T> Drop for TaskHandle<T> {
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
