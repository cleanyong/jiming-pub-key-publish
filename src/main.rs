use axum::{
    Form, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use sqlx::{
    FromRow, SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use std::{env, net::SocketAddr};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize, FromRow)]
struct PubKeyRecord {
    id: String,
    public_key: String,
    note: Option<String>,
}

#[derive(Clone)]
struct AppState {
    db: SqlitePool,
    website_name: String,
}

#[derive(Deserialize)]
struct PublishForm {
    public_key: String,
    note: Option<String>,
}

#[tokio::main]
async fn main() {
    // 初始化 SQLite 資料庫
    // 使用單連線連接池，確保所有寫入是序列化的，避免多連線併發寫入競爭
    // 直接在當前工作目錄下打開 ./pubkeys.db，不存在時自動建立。
    let connect_opts = SqliteConnectOptions::new()
        .filename("pubkeys.db")
        .create_if_missing(true);

    let db = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(connect_opts)
        .await
        .expect("failed to connect to SQLite");

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS pub_keys (
            id TEXT PRIMARY KEY,
            public_key TEXT NOT NULL,
            note TEXT
        )
        "#,
    )
    .execute(&db)
    .await
    .expect("failed to create table");

    // 從環境變量讀取網站名稱，默認為 jiming.cleanyong.familybankbank.com
    let website_name = env::var("WEBSITE_NAME")
        .unwrap_or_else(|_| "jiming.cleanyong.familybankbank.com".to_string());

    let state = AppState { db, website_name };

    let app = Router::new()
        .route("/", get(show_form))
        .route("/publish", post(handle_publish))
        .route("/k/:id", get(show_record))
        .with_state(state);

    // 預設在 127.0.0.1:3003 監聽 (axum 0.7 用 axum::serve)
    let addr = SocketAddr::from(([127, 0, 0, 1], 3003));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    println!(
        "Key publish site running at http://{}/",
        listener.local_addr().unwrap()
    );

    axum::serve(listener, app).await.unwrap();
}

async fn show_form() -> Html<String> {
    let html = r#"
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>极名-公钥发布系统 Publish Your Signing Public Key</title>
    <style>
      body { font-family: sans-serif; max-width: 640px; margin: 2rem auto; padding: 0 1rem;
             background-color: #121212; color: #e0e0e0; }
      label { display: block; margin-top: 1rem; }
      textarea, input[type=text] { width: 100%; box-sizing: border-box; background-color: #1e1e1e;
                                   color: #e0e0e0; border: 1px solid #333; border-radius: 4px; padding: 0.4rem; }
      button { margin-top: 1.5rem; padding: 0.5rem 1.2rem; background-color: #2979ff;
               color: #fff; border: none; border-radius: 4px; cursor: pointer; }
      button:hover { background-color: #1565c0; }
      .hint { font-size: 0.9rem; color: #aaa; }
    </style>
  </head>
  <body>
    <h1>极名-公钥发布系统 Publish Your Signing Public Key</h1>
    <p class="hint">
      建議使用 ED25519 (EdDSA) 的 public key，一行 Base64 表示。
    </p>
    <form method="post" action="/publish">
      <label>
        Public key (required):
        <input type="text" name="public_key" required>
      </label>
      <label>
        Note / comment (optional):
        <textarea name="note" rows="3" placeholder="例如：這是我用於簽名訊息的公鑰。"></textarea>
      </label>
      <button type="submit">Publish</button>
    </form>
  </body>
</html>
    "#;

    Html(html.to_string())
}

async fn handle_publish(
    State(state): State<AppState>,
    Form(form): Form<PublishForm>,
) -> impl IntoResponse {
    let trimmed_key = form.public_key.trim().to_string();
    if trimmed_key.is_empty() {
        return (StatusCode::BAD_REQUEST, "public_key must not be empty").into_response();
    }

    if trimmed_key
        .chars()
        .any(|c| c.is_control() || c.is_whitespace())
    {
        return (
            StatusCode::BAD_REQUEST,
            "public_key cannot contain whitespace or control characters",
        )
            .into_response();
    }

    // key 最長 1000 bytes
    if trimmed_key.as_bytes().len() > 1000 {
        return (
            StatusCode::BAD_REQUEST,
            "public_key must be at most 1000 bytes",
        )
            .into_response();
    }

    // 驗證為 Base64，並且解碼後長度為 32 bytes (ED25519 公鑰)
    match STANDARD.decode(&trimmed_key) {
        Ok(bytes) if bytes.len() == 32 => {}
        Ok(_) => {
            return (
                StatusCode::BAD_REQUEST,
                "public_key must be base64 of a 32-byte key (ED25519)",
            )
                .into_response();
        }
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "public_key must be valid base64").into_response();
        }
    }

    let id = Uuid::new_v4().to_string();
    let note = form
        .note
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty());

    // note 最長 100 bytes
    if let Some(ref n) = note {
        if n.as_bytes().len() > 100 {
            return (StatusCode::BAD_REQUEST, "note must be at most 100 bytes").into_response();
        }
    }

    if let Err(e) = sqlx::query!(
        "INSERT INTO pub_keys (id, public_key, note) VALUES (?, ?, ?)",
        id,
        trimmed_key,
        note
    )
    .execute(&state.db)
    .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("database error: {e}"),
        )
            .into_response();
    }

    // 發佈成功後，導向到該 key 的分享頁面
    Redirect::to(&format!("/k/{id}")).into_response()
}

async fn show_record(State(state): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    if let Err(resp) = validate_record_id(&id) {
        return resp.into_response();
    }

    let record = sqlx::query!(
        r#"SELECT id as "id!: String", public_key as "public_key!: String", note as "note?" FROM pub_keys WHERE id = ?"#,
        id
    )
    .fetch_optional(&state.db)
    .await;

    match record {
        Ok(Some(r)) => {
            let r = PubKeyRecord {
                id: r.id,
                public_key: r.public_key,
                note: r.note,
            };
            let full_url = format!("https://{}/k/{}", state.website_name, r.id);
            build_record_page(r, Some(&full_url)).into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, "Key not found").into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("database error: {e}"),
        )
            .into_response(),
    }
}

fn build_record_page(record: PubKeyRecord, full_url: Option<&str>) -> Html<String> {
    let note_html = record
        .note
        .as_deref()
        .map(|n| format!("<p><strong>Note:</strong> {}</p>", html_escape(n)))
        .unwrap_or_else(|| "<p><em>No note provided.</em></p>".to_string());

    let link_html = if let Some(url) = full_url {
        format!(
            r#"<p><strong>Shareable link:</strong></p>
<div style="display:flex; gap:0.5rem; align-items:center;">
  <input id="share-link" type="text" value="{url}" readonly
         style="flex:1; padding:0.4rem; background-color:#1e1e1e; color:#e0e0e0; border:1px solid #333; border-radius:4px;">
  <button type="button" onclick="copyLink()" style="padding:0.4rem 0.8rem; background-color:#2979ff; color:#fff; border:none; border-radius:4px; cursor:pointer;">
    Copy
  </button>
</div>
<p style="font-size:0.85rem; color:#aaa;">Click “Copy” or select the text to share this link.</p>"#,
            url = html_escape(url)
        )
    } else {
        String::new()
    };

    let html = format!(
        r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Published Key {id}</title>
    <style>
      body {{ font-family: sans-serif; max-width: 640px; margin: 2rem auto; padding: 0 1rem;
             background-color: #121212; color: #e0e0e0; }}
      code {{ padding: 0.2rem 0.4rem; background: #1e1e1e; border-radius: 4px; }}
      a {{ color: #90caf9; }}
    </style>
  </head>
  <body>
    <h1>极名-公钥发布系统 Published Signing Public Key</h1>
    <p><strong>ID:</strong> {id}</p>
    <p><strong>Public key:</strong><br><code>{key}</code></p>
    {note}
    {link}
    <hr>
    <p>You can share this link with others so they can obtain your public key.</p>
    <script>
      function copyLink() {{
        const input = document.getElementById('share-link');
        if (!input) return;
        input.select();
        navigator.clipboard && navigator.clipboard.writeText(input.value).catch(() => {{}});
      }}
    </script>
  </body>
</html>
"#,
        id = record.id,
        key = html_escape(&record.public_key),
        note = note_html,
        link = link_html,
    );

    Html(html)
}

/*
async fn show_record(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let record = {
        let guard = state.records.lock().unwrap();
        guard.get(&id).cloned()
    };

    match record {
        Some(r) => {
            let note_html = r
                .note
                .as_deref()
                .map(|n| format!("<p><strong>Note:</strong> {}</p>", html_escape(n)))
                .unwrap_or_else(|| "<p><em>No note provided.</em></p>".to_string());

            let html = format!(
                r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Published Key {id}</title>
    <style>
      body {{ font-family: sans-serif; max-width: 640px; margin: 2rem auto; padding: 0 1rem; }}
      code {{ padding: 0.2rem 0.4rem; background: #f5f5f5; border-radius: 4px; }}
    </style>
  </head>
  <body>
    <h1>Published Signing Public Key</h1>
    <p><strong>ID:</strong> {id}</p>
    <p><strong>Public key:</strong><br><code>{key}</code></p>
    {note}
    <hr>
    <p>You can share this link with others so they can obtain your public key.</p>
  </body>
</html>
"#,
                id = r.id,
                key = html_escape(&r.public_key),
                note = note_html,
            );

            Html(html).into_response()
        }
        None => (StatusCode::NOT_FOUND, "Key not found").into_response(),
    }
}
*/

fn html_escape(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '&' => "&amp;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&#39;".to_string(),
            _ => c.to_string(),
        })
        .collect()
}

fn validate_record_id(id: &str) -> Result<(), (StatusCode, String)> {
    // IDs are stored as UUID v4 strings; reject anything that is not a UUID to avoid
    // accidental SQL injection attempts via the path parameter.
    match Uuid::parse_str(id) {
        Ok(_) => Ok(()),
        Err(_) => Err((
            StatusCode::BAD_REQUEST,
            "invalid record id (must be a UUID)".to_string(),
        )),
    }
}
