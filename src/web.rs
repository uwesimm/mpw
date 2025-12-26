use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use crate::algorithm::generate_password;

pub async fn index() -> impl Responder {
    const HTML: &str = r#"
<!doctype html>
<html>
<head><meta charset="utf-8"><title>mpw generate</title></head>
<body>
  <h1>Generate Password</h1>
  <form id="f">
    <label>user: <input name="user" value="alice"></label><br>
    <label>password: <input name="master_password" value="password"></label><br>
    <label>site: <input name="site_name" value="example.com"></label><br>
    <label>template: <input name="template" value="x"></label><br>
    <label>usage: <input name="usage" value="a"></label><br>
    <button type="button" onclick="send()">Generate</button>
  </form>
  <pre id="out"></pre>
  <script>
  async function send(){
    const f = document.getElementById('f');
    const data = new FormData(f);
    const body = { master_password: data.get('master_password'), user: data.get('user'), site_name: data.get('site_name'), counter: 1, context: '', usage: String(data.get('usage'))[0], template: String(data.get('template'))[0] };
    const res = await fetch('/api/generate', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify(body)});
    const j = await res.json();
    document.getElementById('out').textContent = JSON.stringify(j, null, 2);
  }
  </script>
</body>
</html>
"#;
    HttpResponse::Ok().content_type("text/html; charset=utf-8").body(HTML)
}

#[derive(Deserialize)]
pub struct ApiRequest {
    pub master_password: String,
    pub user: String,
    pub site_name: String,
    pub counter: Option<u32>,
    pub context: Option<String>,
    pub usage: Option<char>,
    pub template: Option<char>,
}

#[derive(Serialize)]
pub struct ApiResponse {
    pub password: String,
}

pub async fn api_generate(req: web::Json<ApiRequest>) -> impl Responder {
    let r = req.into_inner();
    let counter = r.counter.unwrap_or(1);
    let context = r.context.unwrap_or_default();
    let usage = r.usage.unwrap_or('a');
    let template = r.template.unwrap_or('x');

    match generate_password(&r.master_password, &r.user, &r.site_name, counter, &context, usage, template, None) {
        Ok(pw) => HttpResponse::Ok().json(ApiResponse { password: pw }),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}
