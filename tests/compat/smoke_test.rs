use anyhow::{Result, Context as _, ensure, bail};
use bytes::{BytesMut, BufMut as _};
use enclose::enclose;
use std::mem::drop;
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use crate::{TestSuite, TestCase, keys};
use crate::nursery::Nursery;

pub fn collect(suite: &mut TestSuite) {
    suite.add(TestCase::new("smoke_default_compatible", |socket| {
        smoke_test(socket, makiko::ClientConfig::default_compatible_less_secure())
    }));

    suite.add(TestCase::new("smoke_default", |socket| {
        smoke_test(socket, makiko::ClientConfig::default())
    }).except_servers(vec!["lsh"]));


    let cipher_algos = vec![
        (&makiko::cipher::AES128_CTR, vec!["openssh", "dropbear", "paramiko"]),
        (&makiko::cipher::AES192_CTR, vec!["openssh", "paramiko"]),
        (&makiko::cipher::AES256_CTR, vec!["openssh", "dropbear", "paramiko"]),
        (&makiko::cipher::AES128_CBC, vec!["openssh", "paramiko"]),
        (&makiko::cipher::AES192_CBC, vec!["openssh", "paramiko"]),
        (&makiko::cipher::AES256_CBC, vec!["openssh", "paramiko", "lsh"]),
        (&makiko::cipher::CHACHA20_POLY1305, vec!["openssh", "dropbear", "tinyssh"]),
        (&makiko::cipher::AES128_GCM, vec!["openssh"]),
        (&makiko::cipher::AES256_GCM, vec!["openssh"]),
    ];

    let mac_algos = vec![
        (&makiko::mac::HMAC_SHA2_256, vec!["openssh", "dropbear", "paramiko"]),
        (&makiko::mac::HMAC_SHA2_512, vec!["openssh", "paramiko"]),
        (&makiko::mac::HMAC_SHA1, vec!["openssh", "dropbear", "paramiko", "lsh"]),
        (&makiko::mac::HMAC_SHA2_256_ETM, vec!["openssh", "dropbear", "paramiko"]),
        (&makiko::mac::HMAC_SHA2_512_ETM, vec!["openssh", "paramiko"]),
        (&makiko::mac::HMAC_SHA1_ETM, vec!["openssh", "dropbear"]),
    ];

    let kex_algos = vec![
        (&makiko::kex::CURVE25519_SHA256, vec!["openssh", "dropbear", "tinyssh"]),
        (&makiko::kex::CURVE25519_SHA256_LIBSSH, vec!["openssh", "dropbear", "tinyssh", "paramiko"]),
        (&makiko::kex::DIFFIE_HELLMAN_GROUP14_SHA1, vec!["openssh", "dropbear", "paramiko", "lsh"]),
    ];

    let pubkey_algos = vec![
        (&makiko::pubkey::SSH_ED25519, vec!["openssh", "dropbear", "tinyssh", "paramiko"]),
        (&makiko::pubkey::SSH_RSA_SHA1, vec!["openssh", "dropbear", "paramiko", "lsh"]),
    ];

    for (algo, servers) in cipher_algos.into_iter() {
        suite.add(TestCase::new(&format!("smoke_cipher_{}", algo.name), |socket| {
            smoke_test(socket, makiko::ClientConfig::default_compatible_less_secure().with(|c| {
                c.cipher_algos = vec![algo];
            }))
        }).only_servers(servers));
    }

    for (algo, servers) in mac_algos.into_iter() {
        suite.add(TestCase::new(&format!("smoke_mac_{}", algo.name), |socket| {
            smoke_test(socket, makiko::ClientConfig::default_compatible_less_secure().with(|c| {
                c.mac_algos = vec![algo];
            }))
        }).only_servers(servers));
    }

    for (algo, servers) in kex_algos.into_iter() {
        suite.add(TestCase::new(&format!("smoke_kex_{}", algo.name), |socket| {
            smoke_test(socket, makiko::ClientConfig::default_compatible_less_secure().with(|c| {
                c.kex_algos = vec![algo];
            }))
        }).only_servers(servers));
    }

    for (algo, servers) in pubkey_algos.into_iter() {
        suite.add(TestCase::new(&format!("smoke_pubkey_{}", algo.name), |socket| {
            smoke_test(socket, makiko::ClientConfig::default_compatible_less_secure().with(|c| {
                c.server_pubkey_algos = vec![algo];
            }))
        }).only_servers(servers));
    }
}

async fn smoke_test(socket: TcpStream, config: makiko::ClientConfig) -> Result<()> {
    log::debug!("running a smoke test with {:?}", config);
    let (nursery, mut nursery_stream) = Nursery::new();
    let (client, mut client_rx, client_fut) = makiko::Client::open(socket, config)?;

    nursery.spawn(async move {
        client_fut.await.context("error while handling SSH connection")?;
        log::debug!("client future finished");
        Ok(())
    });

    nursery.spawn(async move {
        while let Some(event) = client_rx.recv().await {
            log::debug!("received {:?}", event);
            if let makiko::ClientEvent::ServerPubkey(_pubkey, accept_tx) = event {
                accept_tx.accept();
            }
        }
        log::debug!("client was closed");
        Ok(())
    });

    nursery.spawn(enclose!{(nursery) async move {
        let res = client.auth_password("alice".into(), "alicealice".into()).await?;
        if !matches!(res, makiko::AuthPasswordResult::Success) {
            let res = client.auth_pubkey(
                "alice".into(), keys::alice_ed25519(), &makiko::pubkey::SSH_ED25519).await?;
            if !matches!(res, makiko::AuthPubkeyResult::Success) {
                bail!("could not authenticate")
            }
        }

        let (session, mut session_rx) = client.open_session().await?;

        let (stdout_tx, stdout_rx) = oneshot::channel();
        nursery.spawn(async move {
            let mut stdout = BytesMut::new();
            while let Some(event) = session_rx.recv().await? {
                if let makiko::SessionEvent::StdoutData(chunk) = event {
                    stdout.put(chunk);
                } else if let makiko::SessionEvent::Eof = event {
                    break;
                }
            }
            let _ = stdout_tx.send(stdout.freeze());
            log::debug!("session was closed");
            Ok(())
        });

        session.exec("whoami".as_bytes())
            .context("could not send exec request")?
            .want_reply().await
            .context("could not execute command")?;

        let stdout = stdout_rx.await
            .context("could not get stdout")?;
        log::debug!("received stdout {:?}", stdout);
        ensure!(stdout.as_ref() == "alice\n".as_bytes(), "received stdout: {:?}", stdout);

        client.disconnect(makiko::DisconnectError::by_app())?;
        Ok(())
    }});

    drop(nursery);
    nursery_stream.try_run().await
}
