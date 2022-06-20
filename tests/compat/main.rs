use anyhow::{Result, Context as _};
use bollard::Docker;
use colored::Colorize as _;
use derivative::Derivative;
use futures::future::BoxFuture;
use std::collections::HashSet;
use std::future::Future;
use std::process::ExitCode;
use tokio::net::TcpStream;
use crate::ssh_server::SshServer;

mod auth_test;
mod nursery;
mod session_test;
mod smoke_test;
mod ssh_server;

#[derive(Debug)]
pub struct TestSuite {
    pub cases: Vec<TestCase>,
}

impl TestSuite {
    pub fn new() -> TestSuite {
        TestSuite { cases: Vec::new() }
    }

    pub fn add(&mut self, case: TestCase) {
        self.cases.push(case);
    }
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct TestCase {
    pub name: String,
    #[derivative(Debug = "ignore")]
    pub f: Box<dyn Fn(TcpStream) -> BoxFuture<'static, Result<()>>>,
    pub servers: Option<HashSet<String>>,
}

impl TestCase {
    pub fn new<F, Fut>(name: &str, f: F) -> TestCase
        where F: Fn(TcpStream) -> Fut,
              F: 'static,
              Fut: Future<Output = Result<()>>,
              Fut: Send + Sync + 'static
    {
        TestCase {
            name: name.into(),
            f: Box::new(move |sock| Box::pin(f(sock))),
            servers: None,
        }
    }

    pub fn with_servers(self, servers: Vec<&str>) -> TestCase {
        Self { servers: Some(servers.into_iter().map(|x| x.into()).collect()), .. self }
    }
}

#[derive(Debug)]
struct TestSelector {
    servers: Option<HashSet<String>>,
    test_cases: Option<regex::RegexSet>,
}

#[derive(Debug, Default)]
struct TestResult {
    pass_count: u32,
    fail_count: u32,
    skip_count: u32,
}

#[derive(Debug)]
struct TestCtx {
    docker: Docker,
    selector: TestSelector,
    suite: TestSuite,
    result: TestResult,
}

#[tokio::main]
async fn main() -> ExitCode {
    env_logger::init();

    let args = clap::Command::new("test-compat")
        .arg(clap::Arg::new("server").short('s')
            .takes_value(true)
            .action(clap::ArgAction::Append)
            .multiple_values(true)
            .use_value_delimiter(true)
            .require_value_delimiter(true))
        .arg(clap::Arg::new("case").short('c')
            .takes_value(true)
            .action(clap::ArgAction::Append))
        .get_matches();

    let servers = args.get_many::<String>("server").map(|xs| xs.cloned().collect());
    let test_cases = args.get_many::<String>("case").map(|xs| regex::RegexSet::new(xs).unwrap());
    let selector = TestSelector { servers, test_cases };

    match run_all_tests(selector).await {
        Ok(result) => {
            let (exit, outcome) = 
                if result.fail_count > 0 {
                    (ExitCode::FAILURE, "problems were found".red())
                } else if result.pass_count > 0 {
                    (ExitCode::SUCCESS, "no problems were found".blue())
                } else {
                    (ExitCode::FAILURE, "no tests were run".magenta())
                };
            println!("{}: {} passed, {} failed, {} skipped",
                outcome, result.pass_count, result.fail_count, result.skip_count);
            exit
        },
        Err(err) => {
            println!("{:?}", err);
            println!("{}", "test failed due to an error".red());
            ExitCode::FAILURE
        },
    }
}

async fn run_all_tests(selector: TestSelector) -> Result<TestResult> {
    let server_names = vec![
        "openssh",
        "dropbear",
        "lsh",
        "paramiko",
    ];

    let docker = Docker::connect_with_local_defaults()
        .context("could not connect to docker daemon")?;

    let mut suite = TestSuite::new();
    smoke_test::collect(&mut suite);
    auth_test::collect(&mut suite);
    session_test::collect(&mut suite);

    let mut ctx = TestCtx { docker, selector, suite, result: TestResult::default() };
    for server_name in server_names.into_iter() {
        run_server_tests(&mut ctx, server_name).await?;
    }
    Ok(ctx.result)
}

async fn run_server_tests(ctx: &mut TestCtx, server_name: &str) -> Result<()> {
    if let Some(servers) = ctx.selector.servers.as_ref() {
        if !servers.contains(server_name) {
            return Ok(())
        }
    }

    let server = SshServer::start(&ctx.docker, server_name).await
        .context("could not start SSH server in docker")?;
    let mut any_fail = false;

    println!("testing server {}", server_name.bold());
    for case in ctx.suite.cases.iter() {
        if let Some(servers) = case.servers.as_ref() {
            if !servers.contains(server_name) {
                continue
            }
        }

        if let Some(case_re) = ctx.selector.test_cases.as_ref() {
            if !case_re.is_match(&case.name) {
                ctx.result.skip_count += 1;
                continue
            }
        }

        print!("  test {} ... ", case.name);
        let socket = server.connect().await?;
        log::debug!("opened socket for test case {:?}, local {}, peer {}",
            case.name, socket.local_addr()?, socket.peer_addr()?);

        match (case.f)(socket).await {
            Ok(()) =>  {
                println!("{}", "ok".green());
                ctx.result.pass_count += 1;
            },
            Err(err) => {
                println!("{}: {:#}", "error".red(), err);
                log::error!("test {:?} for server {:?} failed:\n{:?}", case.name, server_name, err);
                any_fail = true;
                ctx.result.fail_count += 1;
            },
        }
    }

    if !any_fail {
        server.stop(&ctx.docker).await
            .context("could not stop SSH server in docker")?;
    } else {
        println!("{}", format!("  we keep {} server running", server_name).bold());
    }
    Ok(())
}
