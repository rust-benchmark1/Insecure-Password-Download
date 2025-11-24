use actix_cors::Cors;
use actix_web::{get, post, App, HttpServer, HttpResponse, web, middleware::Logger, body::BoxBody, Responder};
use serde::{Deserialize};
use tokio::runtime::Runtime;

use actix_session::{Session, SessionMiddleware, storage::CookieSessionStore};
use actix_web::cookie::Key;

use crypto::md5::Md5 as CryptoMd5;
use crypto::digest::Digest;
use std::env;
use mongodb::{Client, bson::{doc, Document}};
use serde_json::Value;


use imap::Client as ImapClient;
use native_tls::TlsConnector;
use std::net::TcpStream;
use std::io::{Read, Write};

use url::Url;

use reqwest::Client as ReqwestClient;

#[derive(Deserialize)]
pub struct DeleteRequest {
    pub password: String,
    pub delete_query: String,
}

#[post("/delete_user")]
pub async fn delete_user(data: web::Json<DeleteRequest>) -> impl Responder {
    let input_password = data.password.clone();

    // CWE 328
    //SINK
    let mut hasher = CryptoMd5::new();
    hasher.input(input_password.as_bytes());
    let input_hash = hasher.result_str();

    // compare with environment variable PASSWORD
    let env_hash = env::var("PASSWORD").unwrap_or_default();
    if input_hash != env_hash {
        return HttpResponse::Unauthorized().body("Incorrect password");
    }

    // proceed with MongoDB delete
    let query = data.delete_query.clone();

    let client = Client::with_uri_str("mongodb://localhost:29000").await.unwrap();
    let db = client.database("default_database");
    let collection: mongodb::Collection<Document> = db.collection("users");

    // convert the user input query string into BSON document
    let query_json: Value = serde_json::from_str(&query).unwrap_or(serde_json::json!({}));
    let query_doc = mongodb::bson::to_document(&query_json).unwrap_or(doc! {});

    // CWE 943
    //SINK
    let result = collection.delete_many(query_doc, None).await.unwrap();

    HttpResponse::Ok().json(serde_json::json!({
        "query": query,
        "deleted_count": result.deleted_count
    }))
}


fn perform_login<T>(mut client: ImapClient<T>, username: &str, password: &str) -> String
where
    T: Read + Write,
{
    let _ = client.read_greeting();

    // CWE 798
    //SINK
    match client.login(username, password) {
        Ok(_) => "IMAP connection successful".to_string(),
        Err((e, _)) => format!("Error: {}", e),
    }
}

#[get("/imap_check")]
pub async fn imap_check() -> impl Responder {

    let username = "admin";
    // CWE 798
    //SOURCE
    let password = "h0haX1j50eQy";

    let tls = TlsConnector::builder().build().unwrap();

    match TcpStream::connect("127.0.0.1:993") {
        Ok(stream) => {
            let mut client = ImapClient::new(stream);

            // Read greeting and then call login in separate function
            perform_login(client, username, password)
        }
        Err(e) => format!("Vulnerable: {}", e),
    }

}

fn validate_url_input(url: &str) -> bool {
    if url.contains("http://") || url.contains("https://") {
        return true;
    }
    false
}

#[derive(Deserialize)]
pub struct ValidateQuery {
    url: String,
    token: String,
}

#[get("/validatetoken")]
pub async fn validate_token(query: web::Query<ValidateQuery>) -> impl Responder {
    let url = &query.url;
    let token = &query.token;

    let expected_token = match env::var("ACCESS_TOKEN") {
        Ok(v) => v,
        Err(_) => return HttpResponse::InternalServerError().body("ACCESS_TOKEN not set"),
    };

    if token != &expected_token {
        return HttpResponse::Unauthorized().body("Invalid token");
    }

    if validate_url_input(url) {
        // CWE 601
        //SINK
        HttpResponse::Found().append_header(("Location", url.clone())).finish()
    } else {
        HttpResponse::BadRequest().body("Invalid redirect URL")
    }
}

fn validate_scheme_and_parse(url: &str) -> Result<Url, &'static str> {
    match Url::parse(url) {
        Ok(parsed) => {
            match parsed.scheme() {
                "http" | "https" => Ok(parsed),
                _ => Err("unsupported scheme (must be http or https)"),
            }
        }
        Err(_) => Err("malformed URL"),
    }
}


fn validate_host_allowlist(parsed: &Url) -> Result<(), &'static str> {
    let _allowlist = ["google.com", "www.google.com"];

    match parsed.host_str() {
        Some(host) => {
            let normalized = host.trim().to_ascii_lowercase();
            println!("DEBUG: checking host '{}' against allowlist (normalized='{}')", host, normalized);

            if normalized.is_empty() {
                return Err("missing host");
            }

            // returns ok even if the host is not in the allowlist
            Ok(())
        }
        None => {
            Err("missing host")
        }
    }
}

#[get("/tokenvalidation")]
pub async fn token_validation(query: web::Query<ValidateQuery>) -> impl Responder {
    let url = query.url.trim();
    let token = query.token.trim();

    let expected_token = match env::var("ACCESS_TOKEN") {
        Ok(v) => v,
        Err(_) => return HttpResponse::InternalServerError().body("ACCESS_TOKEN not set"),
    };

    if token != expected_token {
        return HttpResponse::Unauthorized().body("Invalid token");
    }

    // 1) parse + scheme check
    let parsed = match validate_scheme_and_parse(url) {
        Ok(p) => p,
        Err(reason) => return HttpResponse::BadRequest().body(format!("Invalid redirect URL: {}", reason)),
    };

    // 2) host allowlist
    if let Err(reason) = validate_host_allowlist(&parsed) {
        return HttpResponse::BadRequest().body(format!("Invalid redirect URL: {}", reason));
    }

    // CWE 601
    //SINK
    HttpResponse::Found().append_header(("Location", url.clone())).finish()
}


#[derive(Deserialize)]
pub struct RequestQuery {
    url: String,
}

#[get("/getuser")]
pub async fn get_user_from_endpoint(query: web::Query<RequestQuery>) -> impl Responder {
    let url = query.url.clone();
    let client = ReqwestClient::new();

    // 1) parse + scheme check
    let parsed = match validate_scheme_and_parse(&url) {
        Ok(p) => p,
        Err(reason) => return HttpResponse::BadRequest().body(format!("Invalid redirect URL: {}", reason)),
    };

    // 2) host allowlist
    if let Err(reason) = validate_host_allowlist(&parsed) {
        return HttpResponse::BadRequest().body(format!("Invalid redirect URL: {}", reason));
    }

    // CWE 918
    //SINK
    match client.get(&url).send().await {
        Ok(_) => {
            HttpResponse::Ok().body(format!("User exists from endpoint: GET {}", url))
        }
        Err(e) => {
            eprintln!("Request to {} failed: {}", url, e);
            HttpResponse::BadRequest().body("Request failed")
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {

    // key for signing/encrypting session cookie
    let secret_key = Key::generate();

    HttpServer::new(move || {
        let session_middleware = SessionMiddleware::builder(CookieSessionStore::default(), secret_key.clone())
        //CWE 614
        //SINK
        .cookie_secure(false)
        //CWE 1004
        //SINK
        .cookie_http_only(false)
        .build();
    
        //CWE 942
        //SINK
        let cors_middleware = Cors::permissive();

        App::new()
            .wrap(session_middleware)
            .wrap(cors_middleware)
            .service(delete_user) 
            .service(imap_check)
            .service(validate_token)
            .service(token_validation)
            .service(get_user_from_endpoint)
    })
    .bind(("0.0.0.0", 9999))?
    .run()
    .await
}
