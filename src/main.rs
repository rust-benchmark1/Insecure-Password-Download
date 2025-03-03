#![feature(decl_macro)]
extern crate rocket;
extern crate rocket_contrib;

use md5::Digest;
use rocket::get;
use rocket::http::ContentType;
use rocket::post;
use rocket::request::Form;
use rocket::response::content::Html;
use rocket::response::Content;
use rocket::response::NamedFile;
use rocket::routes;
use rocket::FromForm;

extern crate bcrypt;
extern crate md5;

#[get("/")]
fn index() -> Html<&'static str> {
    Html("
        <head>
            <title>Password Protected Download</title>
        </head>
        <body style='background-color: #090909;'>
            <a href='https://github.com/Club-ECHO/Insecure-Password-Download'><img decoding='async' width='149' height='149' src='https://github.blog/wp-content/uploads/2008/12/forkme_right_darkblue_121621.png?resize=149%2C149' class='attachment-full size-full' alt='Fork me on GitHub' loading='lazy' data-recalc-dims='1' style='position: fixed;right:0;top:0;'></a>
            <form action='' method='post' style='display:flex;flex-direction:column;position:absolute;left:50%;top:50%;transform:translate(-50%,-50%);gap:10px;'>
                <input type='password' id='password' name='password' required style='width:250px;height:32px;border:1px solid limegreen;border-radius:5px;padding-inline:10px;background:transparent;color:limegreen' placeholder='password123'>
                <button type='submit' style='height:48px;width:250px;border:1px solid limegreen;border-radius:5px;background:transparent;color:limegreen;'>Download</button>
            </form>
        </body>
        ")
}

#[post("/", data = "<password_form>")]
fn check_password_1(password_form: Form<PasswordForm>) -> Result<Content<NamedFile>, String> {
    let password: &str = "password123";

    if &password_form.password == password {
        let file: NamedFile = NamedFile::open("level-1-reward").map_err(|e| e.to_string())?;
        let content_type: ContentType = ContentType::new("application", "octet-stream");
        let content: Content<NamedFile> = Content(content_type, file);
        Ok(content)
    } else {
        Err("Incorrect password".to_string())
    }
}

#[post("/2", data = "<password_form>")]
fn check_password_2(password_form: Form<PasswordForm>) -> Result<NamedFile, String> {
    let password_hash: &str = concat!("$", "4b3c48dba10e34087339dd4bb5963d9c");

    let hashed: Digest = md5::compute(&password_form.password.as_bytes());

    if format!("${:x}", hashed) == password_hash {
        Ok(NamedFile::open("level-2-reward").map_err(|e| e.to_string())?)
    } else {
        Err("Incorrect password".to_string())
    }
}

#[post("/3", data = "<password_form>")]
fn check_password_3(password_form: Form<PasswordForm>) -> Result<NamedFile, String> {
    let password_hash: &str = "$2y$10$3u4zfdF1jLMekvEJANCh2eaUaPvoSEbM05efznRN47oPOt.SScuRW";

    if bcrypt::verify(&password_form.password, password_hash).unwrap()
        || password_form.password == password_hash
    {
        // Accept hash for api access
        Ok(NamedFile::open("level-3-reward").map_err(|e| e.to_string())?)
    } else {
        Err("Incorrect password".to_string())
    }
}

#[derive(FromForm)]
struct PasswordForm {
    password: String,
}

fn main() {
    rocket::ignite()
        .mount(
            "/",
            routes![index, check_password_1, check_password_2, check_password_3],
        )
        .mount("/1", routes![index])
        .mount("/2", routes![index])
        .mount("/3", routes![index])
        .launch();
}
