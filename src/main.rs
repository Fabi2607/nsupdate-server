use std::collections::HashMap;
use std::convert::Infallible;
use std::env;
use std::fs;
use std::fs::File;
use std::net::{IpAddr, SocketAddr};
use std::process::{Command, Stdio};
use std::time::SystemTime;

use env_logger;
use log::{error, info};

use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode, Uri};

/// Update DNS record
fn nsupdate(domain: &str, ip: &str, record: &str) {
    let command = match env::var_os("RNU_DEBUG") {
        Some(_) => "cat",
        None => "nsupdate",
    };

    let mut path = env::temp_dir();
    path.push(format!(
        "{}.txt",
        SystemTime::now().elapsed().unwrap().as_nanos()
    ));

    let path = path.as_os_str();

    info!("Performing update for {} type {} with {}", domain, record, ip);

    fs::write(
        path,
        format!(
            "update del {domain} {record}\nupdate add {domain} 60 {record} {ip}\nsend\n",
            domain = domain,
            ip = ip,
            record = record
        ),
    )
    .expect("Could not write file");

    let status = Command::new(command)
        .stdin(Stdio::from(File::open(path).expect("Could not find file")))
        .stdout(Stdio::inherit())
        .status()
        .expect("Failed to execute command");

    if !status.success() {
        println!("Failed to update record");
    }

    fs::remove_file(path).expect("Failed to remove file")
}

/// Validate the API Key
fn validate_api_key(key: &str, domain: &str) -> bool {
    let path = env::var("RNU_AUTH_FILE").unwrap_or("keys".to_string());
    let contents = fs::read_to_string(path).unwrap_or("".to_string());

    internal_validate_api_keys(&*contents, key, domain)
}

fn internal_validate_api_keys(file_content: &str, key: &str, domain: &str) -> bool {
    let api_keys: Vec<&str> = file_content.split("\n").collect();

    api_keys.iter().any(|line| {
        let parts: Vec<&str> = line.split_ascii_whitespace().collect();
        parts == [key, domain]
    })
}

/// Request handler for /update
fn handle_update(uri: &Uri) -> Result<Response<Body>, Infallible> {
    let params: HashMap<String, String> = uri
        .query()
        .map(|v| {
            url::form_urlencoded::parse(v.as_bytes())
                .into_owned()
                .collect()
        })
        .unwrap_or_else(HashMap::new);

    let domain = match params.get("domain") {
        Some(domain) => domain,
        None => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from("Domain must be specified"))
                .unwrap_or(Response::default()))
        }
    };

    let key = match params.get("key") {
        Some(key) => key,
        None => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from("No API Key specified"))
                .unwrap_or(Response::default()))
        }
    };

    if !validate_api_key(key, domain) {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from("Invalid API Key specified"))
            .unwrap_or(Response::default()));
    }

    let mut found = 2;
    match params.get("ip") {
        Some(ip) => nsupdate(domain, ip, "A"),
        None => found -= 1,
    };

    match params.get("ipv6") {
        Some(ip) => nsupdate(domain, ip, "AAAA"),
        None => found -= 1,
    };

    if found <= 0 {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from("Neither ipv4 nor ipv6 update specified"))
            .unwrap_or(Response::default()));
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Body::from("Update successful"))
        .unwrap_or(Response::default()))
}

/// generic request handling
async fn handle_request(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/update") => handle_update(req.uri()),
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("Page not found"))
            .unwrap_or(Response::default())),
    }
}

/// graceful shutdown handler
async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install signal handler")
}

#[tokio::main()]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let ip_address: IpAddr = std::env::var("RNU_HOST")
        .unwrap_or("127.0.0.1".into())
        .parse()
        .expect("Failed to parse IP addr");

    let port: u16 = std::env::var("RNU_PORT")
        .unwrap_or("3000".into())
        .parse()
        .expect("Failed to parse port");

    let addr = SocketAddr::new(ip_address, port);

    info!("Listening on {}", addr);

    let make_svc = make_service_fn(|_conn| async {
        Ok::<_, Infallible>(service_fn(|req| handle_request(req)))
    });

    let server = Server::bind(&addr).serve(make_svc);

    let graceful = server.with_graceful_shutdown(shutdown_signal());

    if let Err(e) = graceful.await {
        error!("Server error: {}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_key_file() {
        assert_eq!(internal_validate_api_keys("", "test", "test"), false);
    }

    #[test]
    fn test_key_file_missing_domain() {
        assert_eq!(internal_validate_api_keys("test", "test", "test"), false);
    }

    #[test]
    fn test_key_file_excess_content() {
        assert_eq!(
            internal_validate_api_keys("test test 3", "test", "test"),
            false
        );
    }

    #[test]
    fn test_key_file_single_line() {
        assert!(internal_validate_api_keys("test test", "test", "test"));
    }

    #[test]
    fn test_key_file_multiline() {
        assert!(internal_validate_api_keys(
            "a a\ntest test\n5 4",
            "test",
            "test"
        ));
    }
}
