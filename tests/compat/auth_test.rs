use anyhow::{Result, ensure, bail, Context as _};
use futures::future::BoxFuture;
use std::future::Future;
use std::time::Duration;
use tokio::net::TcpStream;
use crate::{TestSuite, TestCase, keys};
use crate::nursery::Nursery;

pub fn collect(suite: &mut TestSuite) {
    suite.add(TestCase::new("auth_no_authentication", test_no_authentication));

    suite.add(TestCase::new("auth_password_success", test_password_success)
        .except_servers(vec!["tinyssh"]));
    suite.add(TestCase::new("auth_password_failure", test_password_failure)
        .except_servers(vec!["tinyssh"]));
    suite.add(TestCase::new("auth_password_retry", test_password_retry)
        .except_servers(vec!["tinyssh"]));
    suite.add(TestCase::new("auth_password_already_authenticated", test_password_already_authenticated)
        .except_servers(vec!["tinyssh"]));

    let pubkey_variants = vec![
        (
            "edward",
            vec![("ed25519", keys::edward_ed25519())],
            vec![(&makiko::pubkey::SSH_ED25519, vec!["openssh", "dropbear", "tinyssh", "paramiko"])],
        ),
        (
            "ruth",
            vec![
                ("rsa_1024", keys::ruth_rsa_1024()),
                ("rsa_2048", keys::ruth_rsa_2048()),
                ("rsa_4096", keys::ruth_rsa_4096()),
            ],
            vec![
                (&makiko::pubkey::SSH_RSA_SHA1, vec!["openssh", "dropbear", "lsh", "paramiko"]),
                (&makiko::pubkey::RSA_SHA2_256, vec!["openssh", "dropbear", "paramiko"]),
                (&makiko::pubkey::RSA_SHA2_512, vec!["openssh", "paramiko"]),
            ],
        ),
        (
            "eda",
            vec![("ecdsa_p256", keys::eda_ecdsa_p256())],
            vec![(&makiko::pubkey::ECDSA_SHA2_NISTP256, vec!["openssh", "dropbear", "paramiko"])],
        ),
        (
            "eda",
            vec![("ecdsa_p384", keys::eda_ecdsa_p384())],
            vec![(&makiko::pubkey::ECDSA_SHA2_NISTP384, vec!["openssh", "dropbear", "paramiko"])],
        ),
    ];

    for (username, key_variants, algo_variants) in pubkey_variants.into_iter() {
        for (key_name, privkey) in key_variants.iter() {
            for &(algo, ref servers) in algo_variants.iter() {
                let (username, privkey) = (username.to_string(), privkey.clone());
                let case_name = format!("auth_pubkey_{}_{}_success", key_name, algo.name);
                suite.add(TestCase::new(&case_name, move |socket| {
                    test_pubkey_success(socket, username.clone(), privkey.clone(), algo)
                }).only_servers(servers.clone()));
            }
        }
    }

    suite.add(TestCase::new("auth_pubkey_failure", test_pubkey_failure));
    suite.add(TestCase::new("auth_pubkey_retry", test_pubkey_retry)
        .except_servers(vec!["lsh"]));
    suite.add(TestCase::new("auth_pubkey_already_authenticated", test_pubkey_already_authenticated)
        .except_servers(vec!["lsh"]));
    suite.add(TestCase::new("auth_pubkey_rekey", test_pubkey_rekey)
        .except_servers(vec!["lsh", "tinyssh"]));
    suite.add(TestCase::new("auth_pubkey_algo_names", test_pubkey_algo_names)
        .except_servers(vec!["lsh", "tinyssh"]));

    suite.add(TestCase::new("auth_pubkey_check_true_ed25519",
        |socket| test_pubkey_check(socket,
            "edward".into(), keys::edward_ed25519(), &makiko::pubkey::SSH_ED25519, true))
        .except_servers(vec!["lsh"]));
    suite.add(TestCase::new("auth_pubkey_check_true_rsa",
        |socket| test_pubkey_check(socket,
            "ruth".into(), keys::ruth_rsa_2048(), &makiko::pubkey::SSH_RSA_SHA1, true))
        .except_servers(vec!["tinyssh"]));
    suite.add(TestCase::new("auth_pubkey_check_false_bad_user",
        |socket| test_pubkey_check(socket,
            "eve".into(), keys::edward_ed25519(), &makiko::pubkey::SSH_ED25519, false))
        .except_servers(vec!["tinyssh"]));
    suite.add(TestCase::new("auth_pubkey_check_false_bad_key",
        |socket| test_pubkey_check(socket,
            "edward".into(), keys::ruth_rsa_2048(), &makiko::pubkey::SSH_RSA_SHA1, false)));
    suite.add(TestCase::new("auth_pubkey_check_false_bad_algo",
        |socket| test_pubkey_check(socket,
            "edward".into(), keys::edward_ed25519(), &makiko::pubkey::SSH_RSA_SHA1, false))
        .except_servers(vec!["paramiko"]));

    suite.add(TestCase::new("auth_none_success", test_none_success)
        .except_servers(vec!["tinyssh", "lsh"]));
    suite.add(TestCase::new("auth_none_failure", test_none_failure));
    suite.add(TestCase::new("auth_none_already_authenticated", test_none_already_authenticated)
        .except_servers(vec!["tinyssh", "lsh"]));
}



async fn test_no_authentication(socket: TcpStream) -> Result<()> {
    test_auth(socket, |client| async move {
        check_not_authenticated(client).await
    }).await
}



async fn test_password_success(socket: TcpStream) -> Result<()> {
    test_auth(socket, |client| async move {
        ensure!(!client.is_authenticated()?);
        let res = client.auth_password("alice".into(), "alicealice".into()).await?;
        ensure!(matches!(res, makiko::AuthPasswordResult::Success), "expected success, got {:?}", res);
        check_authenticated(client).await
    }).await
}

async fn test_password_failure(socket: TcpStream) -> Result<()> {
    test_auth(socket, |client| async move {
        let res = client.auth_password("alice".into(), "wrong password".into()).await?;
        match res {
            makiko::AuthPasswordResult::Failure(fail) => {
                ensure!(fail.methods_can_continue.contains(&"password".into()), "{:?}", fail);
                ensure!(!fail.partial_success, "{:?}", fail);
            },
            res => bail!("expected failure, got {:?}", res),
        }
        check_not_authenticated(client).await
    }).await
}

async fn test_password_retry(socket: TcpStream) -> Result<()> {
    test_auth(socket, |client| async move {
        let res = client.auth_password("alice".into(), "wrong password".into()).await?;
        ensure!(matches!(res, makiko::AuthPasswordResult::Failure(_)), "expected failure, got {:?}", res);
        ensure!(!client.is_authenticated()?);
        
        let res = client.auth_password("alice".into(), "alicealice".into()).await?;
        ensure!(matches!(res, makiko::AuthPasswordResult::Success), "expected success, got {:?}", res);
        check_authenticated(client).await
    }).await
}

async fn test_password_already_authenticated(socket: TcpStream) -> Result<()> {
    test_auth(socket, |client| async move {
        let res = client.auth_password("alice".into(), "alicealice".into()).await?;
        ensure!(matches!(res, makiko::AuthPasswordResult::Success), "expected success, got {:?}", res);
        ensure!(client.is_authenticated()?);

        let res = client.auth_password("alice".into(), "wrong password".into()).await?;
        ensure!(matches!(res, makiko::AuthPasswordResult::Success), "expected success, got {:?}", res);
        check_authenticated(client).await
    }).await
}



async fn test_pubkey_success(
    socket: TcpStream,
    username: String,
    privkey: makiko::Privkey,
    algo: &'static makiko::PubkeyAlgo,
) -> Result<()> {
    test_auth(socket, move |client| async move {
        ensure!(!client.is_authenticated()?);
        let res = client.auth_pubkey(username, privkey, algo).await?;
        ensure!(matches!(res, makiko::AuthPubkeyResult::Success), "expected success, got {:?}", res);
        check_authenticated(client).await
    }).await
}

async fn test_pubkey_failure(socket: TcpStream) -> Result<()> {
    test_auth(socket, |client| async move {
        ensure!(!client.is_authenticated()?);
        let res = client.auth_pubkey(
            "edward".into(), keys::ruth_rsa_1024(), &makiko::pubkey::SSH_RSA_SHA1).await?;
        ensure!(matches!(res, makiko::AuthPubkeyResult::Failure(_)), "expected failure, got {:?}", res);
        check_not_authenticated(client).await
    }).await
}

async fn test_pubkey_retry(socket: TcpStream) -> Result<()> {
    test_auth(socket, |client| async move {
        let res = client.auth_pubkey(
            "edward".into(), keys::ruth_rsa_2048(), &makiko::pubkey::SSH_RSA_SHA1).await?;
        ensure!(matches!(res, makiko::AuthPubkeyResult::Failure(_)), "expected failure, got {:?}", res);

        let res = client.auth_pubkey(
            "edward".into(), keys::edward_ed25519(), &makiko::pubkey::SSH_ED25519).await?;
        ensure!(matches!(res, makiko::AuthPubkeyResult::Success), "expected success, got {:?}", res);
        check_authenticated(client).await
    }).await
}

async fn test_pubkey_already_authenticated(socket: TcpStream) -> Result<()> {
    test_auth(socket, |client| async move {
        let res = client.auth_pubkey(
            "edward".into(), keys::edward_ed25519(), &makiko::pubkey::SSH_ED25519).await?;
        ensure!(matches!(res, makiko::AuthPubkeyResult::Success), "expected success, got {:?}", res);
        ensure!(client.is_authenticated()?);

        let res = client.auth_pubkey(
            "edward".into(), keys::ruth_rsa_2048(), &makiko::pubkey::SSH_RSA_SHA1).await?;
        ensure!(matches!(res, makiko::AuthPubkeyResult::Success), "expected success, got {:?}", res);
        check_authenticated(client).await
    }).await
}

async fn test_pubkey_rekey(socket: TcpStream) -> Result<()> {
    test_auth(socket, |client| async move {
        let rekey_res = client.rekey().await;
        ensure!(matches!(rekey_res, Ok(_) | Err(makiko::Error::RekeyRejected)),
            "rekey failed: {:#}", rekey_res.unwrap_err());

        let res = client.auth_pubkey(
            "edward".into(), keys::ruth_rsa_2048(), &makiko::pubkey::SSH_RSA_SHA1).await?;
        ensure!(matches!(res, makiko::AuthPubkeyResult::Failure(_)), "expected failure, got {:?}", res);

        let rekey_res = client.rekey().await;
        ensure!(matches!(rekey_res, Ok(_) | Err(makiko::Error::RekeyRejected)),
            "rekey failed: {:#}", rekey_res.unwrap_err());

        let res = client.auth_pubkey(
            "edward".into(), keys::edward_ed25519(), &makiko::pubkey::SSH_ED25519).await?;
        ensure!(matches!(res, makiko::AuthPubkeyResult::Success), "expected success, got {:?}", res);
        check_authenticated(client).await
    }).await
}

async fn test_pubkey_algo_names(socket: TcpStream) -> Result<()> {
    test_auth(socket, |client| async move {
        let _: makiko::AuthNoneResult = client.auth_none("edward".into()).await?;
        match client.auth_pubkey_algo_names()? {
            Some(names) => ensure!(names.contains(&"ssh-ed25519".into()), "received {:?}", names),
            None => bail!("received None"),
        }
        Ok(())
    }).await
}



async fn test_pubkey_check(
    socket: TcpStream,
    username: String,
    privkey: makiko::Privkey,
    algo: &'static makiko::PubkeyAlgo,
    expected: bool,
) -> Result<()> {
    test_auth(socket, move |client| async move {
        let pubkey = privkey.pubkey();
        let res = client.check_pubkey(username, &pubkey, algo).await?;
        ensure!(res == expected, "expected {}, received {}", expected, res);
        check_not_authenticated(client).await
    }).await
}



async fn test_none_success(socket: TcpStream) -> Result<()> {
    test_auth(socket, |client| async move {
        ensure!(!client.is_authenticated()?);
        let res = client.auth_none("queen".into()).await?;
        ensure!(matches!(res, makiko::AuthNoneResult::Success), "expected success, got {:?}", res);
        check_authenticated(client).await
    }).await
}

async fn test_none_failure(socket: TcpStream) -> Result<()> {
    test_auth(socket, |client| async move {
        let res = client.auth_none("alice".into()).await?;
        ensure!(matches!(res, makiko::AuthNoneResult::Failure(_)), "expected failure, got {:?}", res);
        check_not_authenticated(client).await
    }).await
}

async fn test_none_already_authenticated(socket: TcpStream) -> Result<()> {
    test_auth(socket, |client| async move {
        let res = client.auth_none("queen".into()).await?;
        ensure!(matches!(res, makiko::AuthNoneResult::Success), "expected success, got {:?}", res);
        ensure!(client.is_authenticated()?);

        let res = client.auth_none("queen".into()).await?;
        ensure!(matches!(res, makiko::AuthNoneResult::Success), "expected success, got {:?}", res);
        check_authenticated(client).await
    }).await
}



async fn check_authenticated(client: makiko::Client) -> Result<()> {
    ensure!(client.is_authenticated()?);
    let (_session, _session_rx) = client.open_session(makiko::ChannelConfig::default()).await?;
    Ok(())
}

async fn check_not_authenticated(client: makiko::Client) -> Result<()> {
    ensure!(!client.is_authenticated()?);
    tokio::select! {
        _ = client.open_session(makiko::ChannelConfig::default()) =>
            bail!("session was opened before authentication"),
        _ = tokio::time::sleep(Duration::from_millis(10)) => Ok(()),
    }
}

async fn test_auth<F, Fut>(socket: TcpStream, f: F) -> Result<()>
    where F: FnOnce(makiko::Client) -> Fut + Send + Sync + 'static,
          Fut: Future<Output = Result<()>> + Send + Sync + 'static,
{
    test_auth_inner(socket, Box::new(move |client| Box::pin(f(client)))).await
}

async fn test_auth_inner(
    socket: TcpStream,
    f: Box<dyn FnOnce(makiko::Client) -> BoxFuture<'static, Result<()>> + Sync + Send>,
) -> Result<()> {
    let (nursery, mut nursery_stream) = Nursery::new();
    let config = makiko::ClientConfig::default_compatible_less_secure();
    let (client, mut client_rx, client_fut) = makiko::Client::open(socket, config)?;

    nursery.spawn(async move {
        client_fut.await.context("error while handling SSH connection")?;
        Ok(())
    });

    nursery.spawn(async move {
        while let Some(event) = client_rx.recv().await? {
            if let makiko::ClientEvent::ServerPubkey(_pubkey, accept_tx) = event {
                accept_tx.accept();
            }
        }
        Ok(())
    });

    nursery.spawn(async move {
        f(client.clone()).await?;
        client.disconnect(makiko::DisconnectError::by_app())?;
        Ok(())
    });

    drop(nursery);
    nursery_stream.try_run().await
}
