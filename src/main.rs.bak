extern crate flate2;
use chrono::prelude::Local;
use flate2::read::GzDecoder;
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Request, Response, Server};
use lazy_static::*;
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::str;
use std::sync::Mutex;
use tokio::select;
use tokio::task::JoinHandle;

type HttpClient = Client<hyper::client::HttpConnector>;

#[derive(Serialize, Deserialize, Debug)]
struct Config {
    services: Vec<u16>,
    redirect: String,
    secret: String,
    report: u16,
    log: String,
    rules: Vec<Rule>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Rule {
    client: String,
    port: u16,
}

#[derive(Serialize, Deserialize, Debug)]
struct FormData {
    secret: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Log {
    src_ip: String,
    dst_port: u16,
    path: String,
    params: String,
    header: String,
    body: String,
    method: String,
    status: u16,
    time: String,
    redirect: String,
}

lazy_static! {
    static ref CONFIG: Mutex<Config> = Mutex::new(load_conf().expect("unable to load config"));
    static ref LATEST_CLIENT: Mutex<String> = Mutex::new(String::from(""));
}

#[tokio::main]
/// Start with `RUST_LOG=debug cargo run`
async fn main() {
    env_logger::init();

    info!("{}", "Starting proxy server...");
    let report_addr = SocketAddr::from(([0, 0, 0, 0], CONFIG.lock().unwrap().report));
    let client = Client::builder()
        .http1_title_case_headers(true)
        .http1_preserve_header_case(true)
        .build_http();

    let make_service = make_service_fn(move |conn: &AddrStream| {
        let client = client.clone();
        let src_ip = conn.remote_addr().ip().to_string();
        let port = conn.local_addr().port();
        async move {
            Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
                handler(client.clone(), req, port, src_ip.clone())
            }))
        }
    });

    let make_report = make_service_fn(|_| async { Ok::<_, Infallible>(service_fn(report)) });

    let mut services: Vec<JoinHandle<()>> = Vec::new();
    for port in &CONFIG.lock().unwrap().services {
        info!("Listening on port {}", port);
        let addr = SocketAddr::from(([0, 0, 0, 0], *port));
        let server = Server::bind(&addr).serve(make_service.clone());
        let handle = tokio::spawn(async move {
            if let Err(e) = server.await {
                error!("server error: {}", e);
            }
        });
        services.push(handle);
    }
    let report_server = Server::bind(&report_addr)
        .serve(make_report)
        .with_graceful_shutdown(shutdown_signal());

    select! {
        _ = futures_util::future::join_all(services) => println!("proxy server exit"),
        _ = report_server => println!("report server exit"),
    }
}

/// Proxy request to target service
///
/// * `client`: HTTP client
/// * `req`: request from outside
/// * `port`: request port
/// * `if_shadow`: if the request is redirected to shadow service
/// * `src_ip`: source IP address
async fn handler(
    client: HttpClient,
    req: Request<Body>,
    port: u16,
    src_ip: String,
) -> Result<Response<Body>, hyper::Error> {
    info!("{} {} {} {}", src_ip, req.method(), port, req.uri());
    let now = Local::now();
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let params = req.uri().query().unwrap_or("").to_string();
    let headers = req.headers().clone();
    let body = hyper::body::to_bytes(req.into_body()).await?;
    let body_str = match str::from_utf8(&body) {
        Ok(v) => v.to_string(),
        Err(_e) => String::from(""),
    };
    // let addr_ip = match if_shadow {
    //     true => CONFIG.lock().unwrap().shadow.clone(),
    //     false => CONFIG.lock().unwrap().product.clone(),
    // };
    let redirect_ip = CONFIG.lock().unwrap().redirect.clone();
    let if_shadow = match_rule(src_ip.clone(), port);
    let protocol = match port {
        10250 => "https",
        _ => "http",
    };
    let redirect_port = match if_shadow {
        true => port - 1,
        false => port + 1,
    };
    let target_url = match params.as_str() {
        "" => format!("{}://{}:{}{}", protocol, redirect_ip, redirect_port, path),
        _ => format!(
            "{}://{}:{}{}?{}",
            protocol, redirect_ip, redirect_port, path, params
        ),
    };
    logging(
        now.to_string(),
        src_ip.clone(),
        method.clone(),
        port,
        path,
        params,
        headers.clone(),
        body_str,
        if_shadow,
    );

    let method = match method.as_str() {
        "GET" => hyper::Method::GET,
        "POST" => hyper::Method::POST,
        "PUT" => hyper::Method::PUT,
        "DELETE" => hyper::Method::DELETE,
        _ => hyper::Method::GET,
    };

    let mut request_builder = Request::builder()
        .method(method)
        .uri(target_url)
        .body(Body::from(body))
        .unwrap();

    println!("body: {:?}", request_builder.body());
    info!(
        "proxy to: {} {}",
        request_builder.method(),
        request_builder.uri()
    );

    *request_builder.headers_mut() = headers;
    let response = client.request(request_builder).await?;
    // Check if the response is gzipped
    if let Some(encoding) = response.headers().get("content-encoding") {
        if encoding == "gzip" {
            // If the response is gzipped, decode it
            let body_bytes = hyper::body::to_bytes(response.into_body()).await?;
            let mut decoder = GzDecoder::new(&body_bytes[..]);
            let mut decompressed_body = Vec::new();
            decoder.read_to_end(&mut decompressed_body).unwrap();

            // Create a new response with the decompressed body
            let mut resp = Response::new(Body::from(decompressed_body));
            *resp.status_mut() = hyper::StatusCode::OK;
            let mut latest_client = LATEST_CLIENT.lock().unwrap();
            // Record the latest client IP address
            *latest_client = src_ip.clone();
            return Ok(resp);
        }
    }

    let body = hyper::body::to_bytes(response.into_body()).await?;
    // match str::from_utf8(&body) {
    //     Ok(text) => {
    //         info!("{}", text);
    //     }
    //     Err(e) => {
    //         error!("Invalid UTF-8 sequence: {}", e);
    //     }
    // }

    let mut resp = Response::new(Body::from(body));
    *resp.status_mut() = hyper::StatusCode::OK;
    let mut latest_client = LATEST_CLIENT.lock().unwrap();
    // record the latest client IP address
    *latest_client = src_ip;
    Ok(resp)
}

/// add malicious client to blocklist, these clients will be redirected to shadow service in the
/// future
///
/// * `req`: request from producer cluster
async fn report(mut req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    let whole_body = hyper::body::to_bytes(req.body_mut()).await?;
    let form: FormData = serde_urlencoded::from_bytes(&whole_body).unwrap();

    if form.secret == CONFIG.lock().unwrap().secret {
        let mut latest_client = LATEST_CLIENT.lock().unwrap();
        if latest_client.is_empty() {
            return Ok(Response::new(Body::from("OK")));
        }
        let mut c = CONFIG.lock().unwrap();
        let r = Rule {
            client: latest_client.to_string(),
            port: 0,
        };
        for rule in &c.rules {
            if rule.client == r.client {
                return Ok(Response::new(Body::from("OK")));
            }
        }
        c.rules.push(r);
        warn!("add malicious client: {}", latest_client.to_string());
        latest_client.clear();
    }

    Ok(Response::new(Body::from("OK")))
}

/// check if the client is malicious according to rules
///
/// * `conn`: connection from client
fn match_rule(ip: String, port: u16) -> bool {
    let c = CONFIG.lock().unwrap();
    for rule in &c.rules {
        if rule.client == ip || rule.port == port {
            warn!("malicious: {} {}", ip, port);
            return true;
        }
    }
    false
}

fn load_conf() -> Result<Config, Box<dyn std::error::Error>> {
    info!("{}", "Loading config...");
    let path = "config.json";
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let parsed: Config = serde_json::from_str(&contents)?;

    Ok(parsed)
}

/// logging request
fn logging(
    time: String,
    src_ip: String,
    method: String,
    port: u16,
    path: String,
    params: String,
    headers: hyper::HeaderMap,
    body: String,
    if_shadow: bool,
) {
    let headers = headers
        .iter()
        .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap()))
        .collect::<Vec<String>>()
        .join("\n");

    let log = Log {
        src_ip,
        dst_port: port,
        path,
        params,
        header: headers,
        body,
        method,
        status: 200,
        time,
        redirect: if_shadow.to_string(),
    };

    let json = serde_json::to_string(&log).unwrap();
    let log_file = CONFIG.lock().unwrap().log.clone();
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file)
        .unwrap();
    writeln!(file, "{}", json).unwrap();
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install CTRL+C signal handler");
    info!("shutting down");
    let c = CONFIG.lock().unwrap();
    let serialized = serde_json::to_string_pretty(&*c).unwrap();
    let mut file = File::create("config.json").unwrap();
    file.write_all(serialized.as_bytes()).unwrap();
}
