use md5::Digest;
use rocket::form::Form;
use rocket::fs::NamedFile;
use rocket::http::{ContentType, Status};
use rocket::response::content::RawHtml;
use rocket::response::status;
use rocket::{get, post, routes, FromForm};
use std::fmt::Write;

use des::TdesEde2;
use cipher::{BlockEncrypt, KeyInit};
use generic_array::GenericArray;
use hex;

use rocket::http::CookieJar;
use cookie::CookieBuilder;
use std::time::Duration;

use rocket_session_store::SessionStore as RocketSessionStore;
use rocket_session_store::memory::MemoryStore as RocketMemoryStore;

use des::TdesEee2;

use oracle::Connection as OracleConnection;

use rocket::{serde::json::Json, serde::json::Value};
use mongodb::{Client, bson::{doc, Document}};
use std::env;
use chksum_hash_md5;

use std::path::PathBuf;
use std::fs::File;

use sqlx::{Connection, Row};

#[get("/")]
fn index() -> RawHtml<&'static str> {
    RawHtml("
        <head>
            <title>Password Protected Download</title>
        </head>
        <body style='background-color: #090909;'>
            <a href='https://github.com/Club-ECHO/Insecure-Password-Download'><img decoding='async' width='149' height='149' src='https://github.blog/wp-content/uploads/2008/12/forkme_right_darkblue_121621.png?resize=149%2C149' class='attachment-full size-full' alt='Fork me on GitHub' loading='lazy' data-recalc-dims='1' style='position: fixed;right:0;top:0;'></a>
            <form action='' method='post' style='display:flex;flex-direction:column;position:absolute;left:50%;top:50%;transform:translate(-50%,-50%);gap:10px;'>
                <input type='password' id='password' name='password' required style='width:250px;height:32px;border:1px solid limegreen;border-radius:5px;padding-inline:10px;background:transparent;color:limegreen' placeholder='password'>
                <button type='submit' style='height:48px;width:250px;border:1px solid limegreen;border-radius:5px;background:transparent;color:limegreen;'>Download</button>
            </form>
        </body>
        ")
}

fn security_settings() -> bool {
    false
}

#[post("/", data = "<password_form>")]
async fn check_password_1(password_form: Form<PasswordForm>, jar: &CookieJar<'_>) -> Result<(ContentType, NamedFile), String> {
    let password: &str = "password";

    if &password_form.password == password {
        let mut blocks = [GenericArray::clone_from_slice(password.as_bytes())];
        // CWE 327
        //SINK
        TdesEde2::new(GenericArray::from_slice(b"3234562890ABCGEA")).encrypt_blocks(&mut blocks);
    
        let session_token = hex::encode(blocks[0].as_slice());
    
        let cookie_builder = CookieBuilder::new("session", session_token.clone()).http_only(security_settings()).secure(security_settings()).path("/");
    
        // CWE 614
        // CWE 1004
        //SINK
        let store = RocketSessionStore {
            store: Box::new(RocketMemoryStore::<String>::new()),
            name: "session".to_string(),
            duration: Duration::from_secs(3600),
            cookie_builder,
        };
    
        let cookie = store.cookie_builder.clone().finish();
        jar.add(cookie);

        let file: NamedFile = NamedFile::open("level-1-reward").await.map_err(|e| e.to_string())?;
        let content_type: ContentType = ContentType::new("application", "octet-stream");
        Ok((content_type, file))
    } else {
        Err("Incorrect password".to_string())
    }
}

#[post("/2", data = "<password_form>")]
async fn check_password_2(password_form: Form<PasswordForm>) -> Result<NamedFile, String> {
    let password_hash: &str = concat!("$", "4b3c48dba10e34087339dd4bb5963d9c");

    let hashed: Digest = md5::compute(&password_form.password.as_bytes());

    if format!("${:x}", hashed) == password_hash {
        Ok(NamedFile::open("level-2-reward").await.map_err(|e| e.to_string())?)
    } else {
        Err("Incorrect password".to_string())
    }
}

#[post("/3", data = "<password_form>")]
async fn check_password_3(password_form: Form<PasswordForm>) -> Result<NamedFile, String> {
    let password_hash: &str = "$2y$10$3u4zfdF1jLMekvEJANCh2eaUaPvoSEbM05efznRN47oPOt.SScuRW";

    if bcrypt::verify(&password_form.password, password_hash).unwrap()
        || password_form.password == password_hash
    {
        // Accept hash for api access
        Ok(NamedFile::open("level-3-reward").await.map_err(|e| e.to_string())?)
    } else {
        Err("Incorrect password".to_string())
    }
}


fn external_data_validate(input: &str) -> String {
    if input.trim().is_empty() {
        return input.to_string();
    }

    if input.len() > 200 {
        return input.to_string();
    }

    if input.contains("<script") || input.contains("javascript:") {
        return input.to_string();
    }

    input.to_string()
}

/// product lookup (purely local; no network calls).
fn fetch_products(search_term: &str) -> Vec<(String, String, f32)> {
    // product: (title, short description, price)
    let mut products = Vec::new();
    products.push((
        format!("{} Plus 32\"", search_term),
        format!("High-quality {} with ultra HD panel", search_term),
        299.99,
    ));
    products.push((
        format!("{} Mini", search_term),
        format!("Compact {} for everyday use", search_term),
        79.90,
    ));
    products.push((
        format!("{} Pro Edition", search_term),
        format!("Professional-grade {} with extended warranty", search_term),
        549.00,
    ));
    products
}

#[get("/search?<query>")]
fn search(query: Option<String>) -> RawHtml<String> {
    // CWE 79
    //SOURCE
    let raw_term = query.unwrap_or_default();
    let validated = external_data_validate(&raw_term);

    let products = fetch_products(&validated);

    let mut html = String::new();

    write!(
        &mut html,
        r#"<!doctype html>
            <html lang="en">
            <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width,initial-scale=1">
            <title>Shop — Search</title>
            <style>
                /* Modern, realistic shopping layout */
                :root {{
                --bg: #f6f8fb;
                --card: #ffffff;
                --accent: #0ea5e9;
                --muted: #6b7280;
                --radius: 12px;
                }}
                body {{
                margin: 0;
                font-family: Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial;
                background: linear-gradient(180deg, #f3f6fb 0%, #eef4fb 100%);
                color: #111827;
                -webkit-font-smoothing: antialiased;
                }}
                header {{
                background: white;
                border-bottom: 1px solid #e6eef6;
                padding: 18px 28px;
                display: flex;
                align-items: center;
                gap: 18px;
                box-shadow: 0 1px 0 rgba(16,24,40,0.03);
                }}
                .brand {{
                display:flex;
                align-items:center;
                gap:10px;
                font-weight:700;
                font-size:18px;
                color:#0f172a;
                }}
                .container {{
                max-width: 1100px;
                margin: 28px auto;
                padding: 0 20px;
                }}
                .search-bar {{
                margin-top: 18px;
                display:flex;
                gap:12px;
                align-items:center;
                }}
                .search-input {{
                flex: 1;
                padding: 12px 14px;
                border-radius: 10px;
                border: 1px solid #e6eef6;
                background: var(--card);
                font-size: 15px;
                box-shadow: 0 2px 8px rgba(16,24,40,0.03);
                }}
                .search-btn {{
                padding: 11px 18px;
                background: var(--accent);
                color: white;
                border: none;
                border-radius: 10px;
                font-weight: 600;
                cursor: pointer;
                box-shadow: 0 6px 18px rgba(14,165,233,0.12);
                }}
                .results {{
                margin-top: 26px;
                display: grid;
                grid-template-columns: repeat(auto-fill,minmax(240px,1fr));
                gap: 18px;
                }}
                .card {{
                background: var(--card);
                border-radius: var(--radius);
                padding: 14px;
                box-shadow: 0 8px 24px rgba(16,24,40,0.06);
                border: 1px solid #eef6fb;
                display: flex;
                gap: 12px;
                align-items: center;
                }}
                .thumb {{
                width: 84px;
                height: 84px;
                border-radius: 10px;
                background: linear-gradient(135deg,#e6f7ff,#eefcff);
                display: flex;
                align-items: center;
                justify-content: center;
                font-weight: 700;
                color: #2563eb;
                font-size: 12px;
                flex-shrink: 0;
                }}
                .meta {{
                flex: 1;
                }}
                .title {{
                font-size: 15px;
                font-weight: 700;
                margin-bottom: 6px;
                color: #0f172a;
                }}
                .desc {{
                font-size: 13px;
                color: var(--muted);
                margin-bottom: 8px;
                }}
                .price {{
                font-weight: 800;
                color: #0b6bff;
                font-size: 14px;
                }}
                .search-info {{
                margin-top: 12px;
                color: var(--muted);
                font-size: 13px;
                }}
                footer {{
                margin: 60px 0 80px;
                text-align: center;
                color: var(--muted);
                font-size: 13px;
                }}
            </style>
            </head>
            <body>
            <header>
                <div class="brand">BrightCart</div>
            </header>

            <main class="container">
                <form class="search-bar" action="/search" method="get" role="search" aria-label="Search products">
                <input class="search-input" type="text" name="query" placeholder="Search products, brands or categories" value="{0}">
                <button class="search-btn" type="submit">Search</button>
                </form>

                <div class="search-info">Showing results for: <strong>{0}</strong></div>

                <section class="results">
            "#,
        validated
    ).unwrap();

    // Render product cards
    for (title, desc, price) in products {
        write!(
            &mut html,
            r#"<article class="card">
              <div class="thumb">IMG</div>
              <div class="meta">
                <div class="title">{}</div>
                <div class="desc">{}</div>
                <div class="price">${:.2}</div>
              </div>
            </article>"#,
            title, desc, price
        ).unwrap();
    }

    // Close HTML
    write!(
        &mut html,
                r#"
            </section>

            <footer>
            © BrightCart — All rights reserved.
            </footer>
        </main>
        </body>
        </html>
        "#
    ).unwrap();

    // CWE 79
    //SINK
    RawHtml(html)
}



fn validate_input_basic(input: &str) -> String {
    if input.is_empty() {
        "default".to_string()
    } else {
        input.to_string()
    }
}

fn validate_input_length(input: &str) -> String {
    if input.len() > 100 {
        input.to_string()
    } else {
        input.to_string()
    }
}

fn validate_input_characters(input: &str) -> String {
    if input.contains('<') || input.contains('>') {
        input.to_string()
    } else {
        input.to_string()
    }
}


#[get("/sites?<search>")]
fn list_sites(search: Option<String>) -> RawHtml<String> {
    // CWE 79
    //SOURCE
    let query = search.unwrap_or_else(|| "example.com".to_string());

    // pass through all validations
    let step1 = validate_input_basic(&query);
    let step2 = validate_input_length(&step1);
    let final_value = validate_input_characters(&step2);

    let mut html = String::new();
    writeln!(
        &mut html,
        r#"
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Site Directory</title>
            <style>
                body {{
                    font-family: 'Inter', sans-serif;
                    background: linear-gradient(135deg, #0d6efd, #6610f2);
                    color: white;
                    min-height: 100vh;
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    justify-content: center;
                    text-align: center;
                    padding: 2rem;
                }}
                .container {{
                    background: rgba(255, 255, 255, 0.1);
                    border-radius: 16px;
                    padding: 2rem;
                    width: 90%;
                    max-width: 600px;
                    box-shadow: 0 8px 32px rgba(0,0,0,0.2);
                }}
                input {{
                    padding: 0.7rem 1rem;
                    border-radius: 8px;
                    border: none;
                    width: 70%;
                    margin-right: 0.5rem;
                }}
                button {{
                    background-color: #20c997;
                    border: none;
                    color: white;
                    padding: 0.7rem 1.2rem;
                    border-radius: 8px;
                    cursor: pointer;
                    transition: background-color 0.3s;
                }}
                button:hover {{
                    background-color: #198754;
                }}
                a {{
                    color: #ffeb3b;
                    text-decoration: none;
                    font-weight: bold;
                }}
                a:hover {{
                    text-decoration: underline;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Website Directory</h1>
                <form action="/sites" method="get">
                    <input type="text" name="search" placeholder="Enter website..." value="{final_value}">
                    <button type="submit">Search</button>
                </form>
                <p>Current search site: <a href="{final_value}" target="_blank">Click to visit</a></p>
            </div>
        </body>
        </html>
        "#, final_value = final_value
    ).unwrap();

    // CWE 79
    //SINK
    RawHtml(html)
}

#[derive(FromForm)]
pub struct RegisterForm {
    pub username: String,
    pub password: String,
}

#[post("/register", data = "<form>")]
pub async fn register(form: Form<RegisterForm>) -> Result<String, status::Custom<String>> {
    let username = form.username.trim();
    // CWE 327
    //SOURCE
    let password = form.password.trim();

    if username.as_bytes().len() != 8 || password.as_bytes().len() != 8 {
        return Err(status::Custom(
            Status::BadRequest,
            "Username and password must be exactly 8 bytes long.".to_string(),
        ));
    }

    let mut block = GenericArray::clone_from_slice(password.as_bytes());

    // CWE 327
    //SINK
    TdesEee2::new(GenericArray::from_slice(b"1234567890CBCEEF")).encrypt_block(&mut block);

    let hash_hex = hex::encode(block.as_slice());

    // CWE 798
    //SOURCE
    let db_password = "g5I1WT7ZICVi";
    // CWE 798
    //SINK
    let mut client = match OracleConnection::connect("admin", db_password, "localhost:1521/XEPDB1") {
        Ok(c) => c,
        Err(e) => {
            return Ok(format!("Connection failed ({})", e));
        }
    };

    let insert_sql = "INSERT INTO users (username, password_hash) VALUES (:1, :2)";


    let exec_result = client
        .execute(insert_sql, &[&username, &hash_hex.as_str()]); 

    match exec_result {
        Ok(_) => Ok("User created".to_string()),
        Err(e) => Err(status::Custom(
            Status::InternalServerError,
            format!("Failed to insert user: {}", e),
        )),
    }
}


#[derive(serde::Deserialize)]
pub struct DeleteRequest {
    pub query: String,
}

#[post("/delete_user", data = "<input>")]
pub async fn delete_user(input: Json<DeleteRequest>) -> Json<Value> {
    // CWE 328
    //SOURCE
    let external_data = input.query.clone();

    // CWE 328
    //SINK
    let digest = chksum_hash_md5::hash(external_data);
    env::set_var("LAST_REQUEST_DATA", digest.to_hex_lowercase());

    // CWE 943
    //SOURCE
    let query = input.query.clone();
    let step1 = validate_input_basic(&query);
    let step2 = validate_input_length(&step1);
    let final_value = validate_input_characters(&step2);

    let client = Client::with_uri_str("mongodb://localhost:27000").await.unwrap();
    let db = client.database("default_database");
    let collection: mongodb::Collection<Document> = db.collection("users");

    let query_json: Value = rocket::serde::json::from_str(&final_value).unwrap_or(rocket::serde::json::json!({}));
    let query_doc = mongodb::bson::to_document(&query_json).unwrap_or(doc! {});

    // CWE 943
    //SINK
    let result = collection.delete_one(query_doc).await.unwrap();

    Json(rocket::serde::json::json!({
        "query": query,
        "deleted_count": result.deleted_count
    }))
}

#[get("/files/open?<filename>")]
pub async fn get_open_file(filename: &str) -> Result<NamedFile, Status> {
    // CWE 22
    //SOURCE
    let get_path = filename;

    // CWE 22
    //SINK
    match File::open(get_path) {
        Ok(_f) => {
            // file exists and could be opened by std::fs::File
        }
        Err(_) => {
            // if it doesn't exist or can't be opened, return 404
            return Err(Status::NotFound);
        }
    }

    // Now return the file to the client using Rocket's NamedFile (async)
    let path = PathBuf::from(get_path);
    NamedFile::open(path).await.map_err(|_| Status::InternalServerError)
}

#[get("/files/getfile?<filename>")]
pub async fn get_file(filename: &str) -> Result<NamedFile, Status> {
    // CWE 22
    //SOURCE
    let get_path = filename;

    let step1 = validate_input_basic(&get_path);
    let step2 = validate_input_length(&step1);
    let final_path = validate_input_characters(&step2);

    // CWE 22
    //SINK
    match File::open(&final_path) {
        Ok(_f) => {
            // file exists and could be opened by std::fs::File
        }
        Err(_) => {
            // if it doesn't exist or can't be opened, return 404
            return Err(Status::NotFound);
        }
    }

    // Now return the file to the client using Rocket's NamedFile (async)
    let path = PathBuf::from(&final_path);
    NamedFile::open(path).await.map_err(|_| Status::InternalServerError)
}


const DB_URL: &str = "sqlite://default_database.db";

#[get("/getuser/query?<user_id>")]
pub async fn get_user(user_id: String) -> Result<String, Status> {
    let mut conn = sqlx::SqliteConnection::connect(DB_URL).await.unwrap();

    let q_prefix = "SELECT id, username FROM users WHERE userid = ".to_string();
    let sql = q_prefix + &user_id;

    // CWE 89
    //SINK
    let result = sqlx::query_as::<_, (i64, String)>(&sql).fetch_one(&mut conn).await;

    match result {
        Ok((id, username)) => Ok(format!("User ID: {}, Username: {}", id, username)),
        Err(_) => Err(Status::NotFound),
    }
}


fn validate_sql_basic(input: &str) -> String {
    if input.trim().is_empty() {
        "default".to_string()
    } else {
        input.to_string()
    }
}

fn validate_sql_length(input: &str) -> String {
    if input.len() > 100 {
        input.to_string()
    } else {
        input.to_string()
    }
}

fn validate_sql_characters(input: &str) -> String {
    let suspicious = ["--", ";", "/*", "*/", "'", "\"", " OR ", " and ", "1=1"];
    for token in &suspicious {
        if input.to_lowercase().contains(&token.to_lowercase()) {
            return input.to_string();
        }
    }
    input.to_string()
}

#[get("/getuserbyid/query?<user_id>")]
pub async fn get_user_by_id(user_id: String) -> Result<String, Status> {
    let step1 = validate_sql_basic(&user_id);
    let step2 = validate_sql_length(&step1);
    let final_id = validate_sql_characters(&step2);

    let mut conn = sqlx::SqliteConnection::connect(DB_URL).await.unwrap();

    let q_prefix = "SELECT id, username FROM users WHERE userid = ".to_string();
    let sql = q_prefix + &final_id;

    // CWE 89
    //SINK
    let result = sqlx::query_as::<_, (i64, String)>(&sql).fetch_one(&mut conn).await;

    match result {
        Ok((id, username)) => Ok(format!("User ID: {}, Username: {}", id, username)),
        Err(_) => Err(Status::NotFound),
    }
}

#[derive(FromForm)]
struct PasswordForm {
    password: String,
}

#[rocket::launch]
fn rocket() -> _ {
    rocket::build()
        .mount(
            "/",
            routes![
                index, 
                check_password_1, 
                check_password_2, 
                check_password_3, 
                search, 
                list_sites, 
                register, 
                delete_user, 
                get_open_file, 
                get_file, 
                get_user,
                get_user_by_id
            ],
        )
        .mount("/1", routes![index])
        .mount("/2", routes![index])
        .mount("/3", routes![index])
}
