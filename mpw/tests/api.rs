use actix_web::body::to_bytes;
use actix_web::http::StatusCode;
use actix_web::{test, App};
use mpw::{api_generate, index};
use serde_json::json;

#[actix_web::test]
async fn test_index_page() {
    let app = test::init_service(App::new().route("/", actix_web::web::get().to(index))).await;
    let req = test::TestRequest::get().uri("/").to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    let body = to_bytes(resp.into_body()).await.unwrap();
    let body = String::from_utf8_lossy(&body);
    assert!(body.contains("Generate Password"));
    // The demo page must not ship a pre-filled master password.
    assert!(!body.contains(r#"name="master_password" type="password" value="password""#));
}

#[actix_web::test]
async fn test_api_generate() {
    let app = test::init_service(
        App::new().route("/api/generate", actix_web::web::post().to(api_generate)),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/api/generate")
        .set_json(json!({
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

#[actix_web::test]
async fn test_api_generate_different_templates() {
    let app = test::init_service(
        App::new().route("/api/generate", actix_web::web::post().to(api_generate)),
    )
    .await;

    for template in ["x", "l", "m", "s", "p"] {
        let req = test::TestRequest::post()
            .uri("/api/generate")
            .set_json(json!({
                "master_password": "password",
                "user": "bob",
                "site_name": "mysite",
                "counter": 1,
                "context": "",
                "usage": "a",
                "template": template
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success(), "Template {} failed", template);
        let body = to_bytes(resp.into_body()).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(v.get("password").is_some());
    }
}

#[actix_web::test]
async fn test_api_generate_different_usage_types() {
    let app = test::init_service(
        App::new().route("/api/generate", actix_web::web::post().to(api_generate)),
    )
    .await;

    for usage in ["a", "i", "r"] {
        let req = test::TestRequest::post()
            .uri("/api/generate")
            .set_json(json!({
                "master_password": "password",
                "user": "bob",
                "site_name": "mysite",
                "counter": 1,
                "context": "",
                "usage": usage,
                "template": "x"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success(), "Usage {} failed", usage);
        let body = to_bytes(resp.into_body()).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(v.get("password").is_some());
    }
}

#[actix_web::test]
async fn test_api_generate_with_context() {
    let app = test::init_service(
        App::new().route("/api/generate", actix_web::web::post().to(api_generate)),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/api/generate")
        .set_json(json!({
            "master_password": "password",
            "user": "bob",
            "site_name": "mysite",
            "counter": 1,
            "context": "mycontext",
            "usage": "a",
            "template": "x"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    let body = to_bytes(resp.into_body()).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let password = v.get("password").unwrap().as_str().unwrap();
    assert_eq!(password.len(), 20); // x template yields 20 chars
}

#[actix_web::test]
async fn test_api_generate_matches_reference_at_counter_128() {
    // Regression guard: counter byte 0x80 must be written as a raw byte.
    let app = test::init_service(
        App::new().route("/api/generate", actix_web::web::post().to(api_generate)),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/api/generate")
        .set_json(json!({
            "master_password": "password",
            "user": "user",
            "site_name": "example.com",
            "counter": 128,
            "context": "",
            "usage": "a",
            "template": "l"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    let body = to_bytes(resp.into_body()).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        v.get("password").unwrap().as_str().unwrap(),
        "Cige0%KexdVagd"
    );
}

#[actix_web::test]
async fn test_api_generate_unicode() {
    let app = test::init_service(
        App::new().route("/api/generate", actix_web::web::post().to(api_generate)),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/api/generate")
        .set_json(json!({
            "master_password": "密码",
            "user": "用户",
            "site_name": "站点",
            "counter": 1,
            "context": "上下文",
            "usage": "a",
            "template": "x"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    let body = to_bytes(resp.into_body()).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let password = v.get("password").unwrap().as_str().unwrap();
    assert_eq!(password.chars().count(), 20);
}

#[actix_web::test]
async fn test_api_generate_different_counters_produce_different_passwords() {
    let app = test::init_service(
        App::new().route("/api/generate", actix_web::web::post().to(api_generate)),
    )
    .await;

    let mut passwords = std::collections::HashSet::new();
    for counter in [1, 2, 3, 5, 10] {
        let req = test::TestRequest::post()
            .uri("/api/generate")
            .set_json(json!({
                "master_password": "password",
                "user": "bob",
                "site_name": "mysite",
                "counter": counter,
                "context": "",
                "usage": "a",
                "template": "x"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
        let body = to_bytes(resp.into_body()).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let password = v.get("password").unwrap().as_str().unwrap();
        passwords.insert(password.to_string());
    }

    assert_eq!(
        passwords.len(),
        5,
        "All counter values should produce different passwords"
    );
}

#[actix_web::test]
async fn test_api_generate_no_cors_headers() {
    // The API is same-origin only; responses must not carry wildcard CORS
    // headers that would let any web page read generated passwords.
    let app = test::init_service(
        App::new().route("/api/generate", actix_web::web::post().to(api_generate)),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/api/generate")
        .set_json(json!({
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
    assert!(!resp.headers().contains_key("Access-Control-Allow-Origin"));
}

#[actix_web::test]
async fn test_api_generate_empty_master_password() {
    let app = test::init_service(
        App::new().route("/api/generate", actix_web::web::post().to(api_generate)),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/api/generate")
        .set_json(json!({
            "master_password": "",
            "user": "bob",
            "site_name": "mysite",
            "counter": 1,
            "context": "",
            "usage": "a",
            "template": "p"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(resp.into_body()).await.unwrap();
    assert!(String::from_utf8_lossy(&body).contains("master_password must not be empty"));
}

#[actix_web::test]
async fn test_api_generate_empty_body_is_bad_request() {
    // Omitting required fields must not silently derive from empty strings.
    let app = test::init_service(
        App::new().route("/api/generate", actix_web::web::post().to(api_generate)),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/api/generate")
        .set_json(json!({}))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[actix_web::test]
async fn test_api_generate_zero_counter() {
    let app = test::init_service(
        App::new().route("/api/generate", actix_web::web::post().to(api_generate)),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/api/generate")
        .set_json(json!({
            "master_password": "password",
            "user": "bob",
            "site_name": "mysite",
            "counter": 0,
            "context": "",
            "usage": "a",
            "template": "p"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(resp.into_body()).await.unwrap();
    assert!(String::from_utf8_lossy(&body).contains("counter must be at least 1"));
}

#[actix_web::test]
async fn test_api_generate_invalid_usage() {
    let app = test::init_service(
        App::new().route("/api/generate", actix_web::web::post().to(api_generate)),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/api/generate")
        .set_json(json!({
            "master_password": "password",
            "user": "bob",
            "site_name": "mysite",
            "counter": 1,
            "context": "",
            "usage": "z",
            "template": "p"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(resp.into_body()).await.unwrap();
    assert!(String::from_utf8_lossy(&body).contains("usage character"));
}

#[actix_web::test]
async fn test_api_generate_invalid_template() {
    let app = test::init_service(
        App::new().route("/api/generate", actix_web::web::post().to(api_generate)),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/api/generate")
        .set_json(json!({
            "master_password": "password",
            "user": "bob",
            "site_name": "mysite",
            "counter": 1,
            "context": "",
            "usage": "a",
            "template": "z"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(resp.into_body()).await.unwrap();
    assert!(String::from_utf8_lossy(&body).contains("template"));
}
