//! Embedded read-only console. The shell is public; data uses existing API auth.
use axum::{Router, http::header, response::IntoResponse, routing::get};

const HTML: &str = include_str!("../ui/index.html");
const SCRIPT: &str = include_str!("../ui/app.js");
const STYLE: &str = include_str!("../ui/style.css");
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

fn asset(content_type: &'static str, body: &'static str) -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "no-store"),
            (header::CONTENT_SECURITY_POLICY, CSP),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::REFERRER_POLICY, "no-referrer"),
        ],
        body,
    )
}

pub fn router() -> Router {
    Router::new()
        .route(
            "/ui",
            get(|| async { asset("text/html; charset=utf-8", HTML) }),
        )
        .route(
            "/ui/",
            get(|| async { asset("text/html; charset=utf-8", HTML) }),
        )
        .route(
            "/ui/app.js",
            get(|| async { asset("text/javascript; charset=utf-8", SCRIPT) }),
        )
        .route(
            "/ui/style.css",
            get(|| async { asset("text/css; charset=utf-8", STYLE) }),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn embedded_assets_have_isolation_headers_and_fixed_routes()
    -> Result<(), Box<dyn std::error::Error>> {
        for (path, content_type) in [
            ("/ui", "text/html; charset=utf-8"),
            ("/ui/", "text/html; charset=utf-8"),
            ("/ui/app.js", "text/javascript; charset=utf-8"),
            ("/ui/style.css", "text/css; charset=utf-8"),
        ] {
            let response = router()
                .oneshot(Request::builder().uri(path).body(Body::empty())?)
                .await?;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()[header::CONTENT_TYPE], content_type);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert_eq!(response.headers()[header::CONTENT_SECURITY_POLICY], CSP);
            assert_eq!(
                response.headers()[header::X_CONTENT_TYPE_OPTIONS],
                "nosniff"
            );
            assert_eq!(response.headers()[header::REFERRER_POLICY], "no-referrer");
            assert!(!to_bytes(response.into_body(), 128 * 1024).await?.is_empty());
        }
        for path in ["/ui/missing.js", "/ui/../main.rs"] {
            let response = router()
                .oneshot(Request::builder().uri(path).body(Body::empty())?)
                .await?;
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }
        let response = router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/ui")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        Ok(())
    }
}
