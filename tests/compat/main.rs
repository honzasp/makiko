use anyhow::{Result, Context as _};
use bollard::Docker;
use colored::Colorize as _;
use derivative::Derivative;
use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::process::ExitCode;
use tokio::net::TcpStream;
use crate::ssh_server::SshServer;

mod nursery;
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
    pub f: Box<dyn Fn(TcpStream) -> Pin<Box<dyn Future<Output = Result<()>> + Send + Sync + 'static>>>,
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

#[tokio::main]
async fn main() -> ExitCode {
    env_logger::init();

    match run_all_tests().await {
        Ok((pass_count, 0)) => {
            println!("{}, {} passed", "no problems were found".blue(), pass_count);
            ExitCode::SUCCESS
        },
        Ok((pass_count, fail_count)) => {
            println!("{}, {} passed, {} failed", "problems were found".red(), pass_count, fail_count);
            ExitCode::FAILURE
        },
        Err(err) => {
            println!("{:?}", err);
            println!("{}", "test failed due to an error".red());
            ExitCode::FAILURE
        },
    }
}

async fn run_all_tests() -> Result<(u32, u32)> {
    let server_names = vec![
        "openssh",
        "dropbear",
        "lsh",
        "paramiko",
    ];

    let docker = Docker::connect_with_local_defaults()
        .context("could not connect to docker daemon")?;

    let mut test_suite = TestSuite::new();
    smoke_test::collect(&mut test_suite);

    let (mut all_pass_count, mut all_fail_count) = (0, 0);
    for server_name in server_names.into_iter() {
        let (pass_count, fail_count) = run_server_tests(&docker, server_name, &test_suite).await?;
        all_pass_count += pass_count;
        all_fail_count += fail_count;
    }
    Ok((all_pass_count, all_fail_count))
}

async fn run_server_tests(docker: &Docker, server_name: &str, test_suite: &TestSuite) -> Result<(u32, u32)> {
    let server = SshServer::start(&docker, server_name).await
        .context("could not start SSH server in docker")?;

    println!("testing server {}", server_name.bold());
    let (mut pass_count, mut fail_count) = (0, 0);
    for case in test_suite.cases.iter() {
        if let Some(servers) = case.servers.as_ref() {
            if !servers.contains(server_name) {
                continue
            }
        }

        print!("  test {} ... ", case.name);
        let socket = server.connect().await?;
        match (case.f)(socket).await {
            Ok(()) =>  {
                println!("{}", "ok".green());
                pass_count += 1;
            },
            Err(err) => {
                println!("{}", "error".red());
                println!("{:?}", err);
                fail_count += 1;
            },
        }
    }

    server.stop(&docker).await
        .context("could not stop SSH server in docker")?;
    Ok((pass_count, fail_count))
}
