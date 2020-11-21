use std::collections::HashMap;
use std::convert::Infallible;
use std::fs;
use std::fs::File;
use std::net::SocketAddr;
use std::process::{Command, Stdio};

use hyper::{Body, Method, Request, Response, Server, StatusCode, Uri};
use hyper::service::{make_service_fn, service_fn};

/// Update DNS record
fn nsupdate(domain: &str, ip: &str, record: &str) {
    fs::write("entry.nsupdate", format!(
        "update del {domain} {record}\nupdate add {domain} 60 {record} {ip}\nsend\n", domain = domain, ip = ip, record = record)).expect("Could not write file");

    Command::new("cat")
        .stdin(Stdio::from(File::open("entry.nsupdate").expect("Could not find file")))
        .stdout(Stdio::inherit())
        .spawn()
        .expect("Failed to execute command");
}

/// Validate the API Key
fn validate_api_key(_key: &str, _domain: &str) -> bool {
    let contents =
        fs::read_to_string("./keys")
            .unwrap_or("test test".to_string());
    let api_keys: Vec<&str> = contents.split("\n").collect();

    api_keys.iter().any(|line| {
        let parts: Vec<&str> = line.split_ascii_whitespace().collect();
        parts == [_key, _domain]
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
        None => return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from("Domain must be specified"))
            .unwrap_or(Response::default())),
    };

    let key = match params.get("key") {
        Some(key) => key,
        None => return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from("No API Key specified"))
            .unwrap_or(Response::default())),
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
        _ => {
            Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from("Page not found"))
                .unwrap_or(Response::default()))
        }
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
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    let make_svc =
        make_service_fn(|_conn| async { Ok::<_, Infallible>(service_fn(handle_request)) });

    let server = Server::bind(&addr).serve(make_svc);

    let graceful = server.with_graceful_shutdown(shutdown_signal());

    if let Err(e) = graceful.await {
        eprintln!("Server error: {}", e);
    }
}
