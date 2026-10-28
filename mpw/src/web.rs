use std::sync::OnceLock;

use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use masterpassword_rs::{generate_password, is_valid_template, is_valid_usage};

/// Maximum number of scrypt derivations allowed at the same time. Each
/// derivation costs ~0.5–1 s of CPU and ~32 MiB of memory, so unbounded
/// concurrent requests are a trivial denial-of-service vector.
const MAX_CONCURRENT_DERIVATIONS: usize = 4;

fn derivation_semaphore() -> &'static Semaphore {
    static SEMAPHORE: OnceLock<Semaphore> = OnceLock::new();
    SEMAPHORE.get_or_init(|| Semaphore::new(MAX_CONCURRENT_DERIVATIONS))
}

pub async fn index() -> impl Responder {
    const HTML: &str = r#"
<!doctype html>
<html>
<head><meta charset="utf-8"><title>mpw generate</title></head>
<body>
  <h1>Generate Password</h1>
  <form id="f">
    <label>user: <input name="user" value="alice"></label><br>
    <label>password: <input id="master_password" name="master_password" type="password"></label>
    <button type="button" id="togglePassword">Show</button><br>
    <label>site: <input name="site_name" value="example.com"></label><br>
    <label>template: <input name="template" value="x"></label><br>
    <label>usage: <input name="usage" value="a"></label><br>
    <button type="button" id="generateBtn">Generate</button>
  </form>
  <pre id="out"></pre>
  <script>
  function togglePassword(){
    const inp = document.getElementById('master_password');
    const btn = document.getElementById('togglePassword');
    if(inp.type === 'password'){
      inp.type = 'text';
      btn.textContent = 'Hide';
    } else {
      inp.type = 'password';
      btn.textContent = 'Show';
    }
  }
  async function send(){
    const f = document.getElementById('f');
    const data = new FormData(f);
    const body = { master_password: data.get('master_password'), user: data.get('user'), site_name: data.get('site_name'), counter: 1, context: '', usage: String(data.get('usage'))[0], template: String(data.get('template'))[0] };
    const res = await fetch('/api/generate', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify(body)});
    const j = await res.json().catch(() => null);
    document.getElementById('out').textContent = j ? JSON.stringify(j, null, 2) : await res.text();
  }
  document.addEventListener('DOMContentLoaded', function(){
    const toggle = document.getElementById('togglePassword');
    if(toggle) toggle.addEventListener('click', togglePassword);
    const gen = document.getElementById('generateBtn');
    if(gen) gen.addEventListener('click', send);
  });
  </script>
</body>
</html>
"#;
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(HTML)
}

#[derive(Deserialize)]
#[serde(default)]
pub struct ApiRequest {
    pub master_password: String,
    pub user: String,
    pub site_name: String,
    pub counter: u32,
    pub context: String,
    pub usage: char,
    pub template: char,
}

impl Default for ApiRequest {
    fn default() -> Self {
        Self {
            master_password: String::new(),
            user: String::new(),
            site_name: String::new(),
            counter: 1,
            context: String::new(),
            usage: 'a',
            template: 'x',
        }
    }
}

impl ApiRequest {
    /// Validate the request. Returns a human-readable message on failure;
    /// the caller turns that into a `400 Bad Request`.
    fn validate(&self) -> Result<(), String> {
        if self.master_password.is_empty() {
            return Err("master_password must not be empty".to_string());
        }
        if self.user.is_empty() {
            return Err("user must not be empty".to_string());
        }
        if self.site_name.is_empty() {
            return Err("site_name must not be empty".to_string());
        }
        if self.counter < 1 {
            return Err("counter must be at least 1".to_string());
        }
        if !is_valid_usage(self.usage) {
            return Err(format!(
                "usage character '{}' not recognized. Valid options: 'a' (Authentication), 'i' (Login), 'r' (Recovery)",
                self.usage
            ));
        }
        if !is_valid_template(self.template) {
            return Err(format!(
                "template '{}' not recognized. Valid: x=extra, l=long, m=medium, s=short, n=name, b=basic, P=passphrase, p=pin",
                self.template
            ));
        }
        Ok(())
    }
}

#[derive(Serialize)]
pub struct ApiResponse {
    pub password: String,
}

pub async fn api_generate(req: web::Json<ApiRequest>) -> HttpResponse {
    let r = req.into_inner();

    if let Err(msg) = r.validate() {
        return HttpResponse::BadRequest().body(msg);
    }

    // Queue rather than reject: awaiting a permit caps concurrent scrypt work
    // at MAX_CONCURRENT_DERIVATIONS while still serving every request. The
    // permit is held until the response is ready. (Semaphore::acquire only
    // fails once the semaphore is closed, which we never do.)
    let Ok(_permit) = derivation_semaphore().acquire().await else {
        return HttpResponse::InternalServerError().body("password generation failed");
    };

    // Key derivation is CPU-bound; keep it off the async worker threads.
    let derivation = actix_web::rt::task::spawn_blocking(move || {
        generate_password(
            &r.master_password,
            &r.user,
            &r.site_name,
            r.counter,
            &r.context,
            r.usage,
            r.template,
            None,
        )
    })
    .await;

    match derivation {
        Ok(Ok(pw)) => HttpResponse::Ok().json(ApiResponse { password: pw }),
        Ok(Err(e)) => {
            log::error!("password generation failed: {e:#}");
            HttpResponse::InternalServerError().body("password generation failed")
        }
        Err(e) => {
            log::error!("derivation task failed: {e}");
            HttpResponse::InternalServerError().body("password generation failed")
        }
    }
}
