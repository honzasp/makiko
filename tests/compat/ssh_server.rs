use anyhow::{Result, Context as _, ensure};
use bollard::Docker;
use bollard::container::{CreateContainerOptions, RemoveContainerOptions, Config};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

#[derive(Debug)]
pub struct SshServer {
    pub name: String,
    container_id: String,
    addr: SocketAddr,
}

impl SshServer {
    pub async fn start(docker: &Docker, name: &str) -> Result<SshServer> {
        let container_name = format!("makiko-test-{}", name);
        let image_name = format!("makiko-test/{}", name);

        // if the container already exists, force-remove it
        let first_inspect_res = docker.inspect_container(&container_name, None).await;
        if let Ok(_inspect_res) = first_inspect_res {
            log::info!("removing a running container {:?}", container_name);
            let remove_opts = RemoveContainerOptions {
                force: true,
                .. RemoveContainerOptions::default()
            };
            docker.remove_container(&container_name, Some(remove_opts)).await
                .context("could not force-remove running container")?;
        }

        // create and start a new container
        let create_opts = CreateContainerOptions { name: container_name.as_str() };
        let create_config = Config {
            exposed_ports: Some(vec![("22/tcp", HashMap::new())].into_iter().collect()),
            image: Some(image_name.as_str()),
            .. Config::default()
        };
        let create_res = docker.create_container(Some(create_opts), create_config).await
            .context("could not create container")?;

        docker.start_container::<String>(&create_res.id, None).await
            .context("could not start container")?;

        // inspect the container to get its IP address
        let inspect_res = docker.inspect_container(&create_res.id, None).await
            .context("could not inspect started container")?;
        let ip_addr = inspect_res
            .network_settings.context("expected 'network_settings' key")?
            .ip_address.context("expected 'ip_address' key")?
            .parse().context("could not parse 'ip_address'")?;

        log::info!("started SSH server {:?} at {:?} in container {:?}", name, ip_addr, create_res.id);

        let addr = SocketAddr::new(ip_addr, 22);

        // poll the server until it starts accept()-ing
        wait_for_socket(addr).await?;

        Ok(SshServer {
            name: name.into(),
            container_id: create_res.id,
            addr,
        })
    }

    pub async fn stop(&self, docker: &Docker) -> Result<()> {
        let remove_opts = RemoveContainerOptions {
            force: true,
            .. RemoveContainerOptions::default()
        };
        docker.remove_container(&self.container_id, Some(remove_opts)).await
            .context("could not force-remove container")?;
        log::info!("stopped SSH server {:?}", self.name);

        Ok(())
    }

    pub async fn connect(&self) -> Result<TcpStream> {
        TcpStream::connect(self.addr).await
            .context("could not connect to SSH server")
    }
}

async fn wait_for_socket(addr: SocketAddr) -> Result<()> {
    let start_time = Instant::now();
    loop {
        ensure!(Instant::now() - start_time < Duration::from_millis(500),
            "SSH server on {} did not start in time", addr);
        match TcpStream::connect(addr).await {
            Ok(_) => return Ok(()),
            Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
        }
    }
}
