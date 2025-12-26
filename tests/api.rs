use actix_web::{test, App};
use mpw::{api_generate, index};
use actix_web::body::to_bytes;
use serde_json::json;

#[actix_web::test]
async fn test_api_generate() {
    let app = test::init_service(App::new().route("/api/generate", actix_web::web::post().to(api_generate))).await;

    let req = test::TestRequest::post()
        .uri("/api/generate")
        .set_json(&json!({
            "master_password": "password",
            "user": "bob",
            "site_name": "mysite",
            "counter": 1,
            "context": "",
            "usage": "a",
            "template": "p"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    let body = to_bytes(resp.into_body()).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(v.get("password").is_some());
}
