//! Hotel / restaurant order management backend.
//!
//! Single-file Axum + SQLite (via rusqlite) service covering:
//!   - Admin auth (register / login / me) — JWT bearer tokens
//!   - Org (a.k.a. "restaurant") profile + theme
//!   - Tables + QR codes
//!   - Menu (bulk save, matching the frontend's `saveMenu` contract, plus
//!     single-item CRUD)
//!   - Orders: guest placement + tracking, admin listing/status updates,
//!     and a WebSocket that pushes `order:new` / `order:update` in real
//!     time (mirroring the `ORDERS_SOCKET_URL` client code).
//!
//! `orgId` and `restaurantId` are the same identifier throughout — the
//! column/field is called `org_id` everywhere in this file.
//!
//! Run with:
//!   JWT_SECRET=some-long-random-value cargo run
//!
//! Env vars (all optional, sane defaults for local dev):
//!   DATABASE_PATH   default "hotel.db"
//!   CLIENT_ORIGIN   default "https://order.wayfarer.app"  (used to build QR URLs)
//!   JWT_SECRET      default "dev-secret-change-me"  (DO NOT use the default in prod)
//!   PORT            default 8080

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router, async_trait,
    extract::{
        FromRef, FromRequestParts, Path, Query, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
    routing::{get, patch, post, put},
};
use chrono::{DateTime, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
// use rand::rngs::OsRng;
use rusqlite::{Connection, Row, params};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tower_http::cors::CorsLayer;
use uuid::Uuid;

use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};

// =========================================================================
// Error type
// =========================================================================

struct AppError {
    status: StatusCode,
    message: String,
}

impl AppError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
    fn bad_request(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, msg)
    }
    fn not_found(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, msg)
    }
    fn unauthorized(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, msg)
    }
    fn forbidden(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, msg)
    }
    fn internal(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, msg)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let body = Json(serde_json::json!({ "error": self.message }));
        (self.status, body).into_response()
    }
}

impl From<rusqlite::Error> for AppError {
    fn from(e: rusqlite::Error) -> Self {
        match e {
            rusqlite::Error::QueryReturnedNoRows => AppError::not_found("Not found"),
            other => AppError::internal(other.to_string()),
        }
    }
}

impl From<argon2::password_hash::Error> for AppError {
    fn from(e: argon2::password_hash::Error) -> Self {
        AppError::internal(format!("password hashing error: {e}"))
    }
}

impl From<jsonwebtoken::errors::Error> for AppError {
    fn from(e: jsonwebtoken::errors::Error) -> Self {
        AppError::unauthorized(format!("invalid token: {e}"))
    }
}

// =========================================================================
// App state
// =========================================================================

#[derive(Clone)]
struct BroadcastMsg {
    org_id: String,
    payload: String,
}

struct AppState {
    db: Arc<Mutex<Connection>>,
    tx: broadcast::Sender<BroadcastMsg>,
    jwt_secret: String,
    client_origin: String,
}

type SharedState = Arc<AppState>;

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

/// Runs a blocking rusqlite closure on the blocking thread pool.
async fn db_call<F, T>(state: &SharedState, f: F) -> Result<T, AppError>
where
    F: FnOnce(&Connection) -> rusqlite::Result<T> + Send + 'static,
    T: Send + 'static,
{
    let db = state.db.clone();
    tokio::task::spawn_blocking(move || {
        let conn = db.lock().expect("db mutex poisoned");
        f(&conn)
    })
    .await
    .map_err(|e| AppError::internal(e.to_string()))?
    .map_err(AppError::from)
}

// =========================================================================
// DB init + seed
// =========================================================================

fn init_db(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        r#"
        PRAGMA foreign_keys = ON;

        CREATE TABLE IF NOT EXISTS orgs (
            id                  TEXT PRIMARY KEY,
            name                TEXT NOT NULL,
            tagline             TEXT NOT NULL DEFAULT '',
            logo_initial        TEXT NOT NULL DEFAULT '',
            theme_primary       TEXT NOT NULL,
            theme_primary_dark  TEXT NOT NULL,
            theme_accent        TEXT NOT NULL,
            theme_accent_soft   TEXT NOT NULL,
            theme_background    TEXT NOT NULL,
            theme_surface       TEXT NOT NULL,
            theme_text_primary  TEXT NOT NULL,
            theme_text_secondary TEXT NOT NULL,
            theme_border        TEXT NOT NULL,
            created_at          INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS admin_users (
            id             TEXT PRIMARY KEY,
            org_id         TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            name           TEXT NOT NULL,
            email          TEXT NOT NULL UNIQUE,
            password_hash  TEXT NOT NULL,
            created_at     INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS tables (
            id          TEXT PRIMARY KEY,
            org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            name        TEXT NOT NULL,
            seats       INTEGER NOT NULL DEFAULT 2,
            qr_value    TEXT NOT NULL,
            created_at  INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS menu_items (
            id          TEXT PRIMARY KEY,
            org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            category    TEXT NOT NULL,
            name        TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            image       TEXT NOT NULL DEFAULT '',
            portion     TEXT NOT NULL DEFAULT '',
            price       REAL NOT NULL,
            tags        TEXT NOT NULL DEFAULT '[]',
            sort_order  INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS orders (
            id          TEXT PRIMARY KEY,
            org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            table_id    TEXT NOT NULL,
            table_name  TEXT NOT NULL,
            status      TEXT NOT NULL DEFAULT 'new',
            subtotal    REAL NOT NULL,
            tax         REAL NOT NULL,
            total       REAL NOT NULL,
            created_at  INTEGER NOT NULL,
            updated_at  INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS order_items (
            id            TEXT PRIMARY KEY,
            order_id      TEXT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
            menu_item_id  TEXT,
            name          TEXT NOT NULL,
            price         REAL NOT NULL,
            qty           INTEGER NOT NULL,
            note          TEXT NOT NULL DEFAULT ''
        );

        CREATE INDEX IF NOT EXISTS idx_tables_org ON tables(org_id);
        CREATE INDEX IF NOT EXISTS idx_menu_items_org ON menu_items(org_id);
        CREATE INDEX IF NOT EXISTS idx_orders_org_created ON orders(org_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_orders_table ON orders(org_id, table_id);
        CREATE INDEX IF NOT EXISTS idx_order_items_order ON order_items(order_id);
        "#,
    )
}

/// Seeds a demo org ("123" / The Wayfarer) with a couple of tables, a menu,
/// and one in-progress order — matching the dummy data used on the
/// frontend so the two sides line up out of the box. Only runs once.
fn seed_demo_data(conn: &Connection, client_origin: &str) -> rusqlite::Result<()> {
    let existing: i64 = conn.query_row("SELECT COUNT(*) FROM orgs", [], |r| r.get(0))?;
    if existing > 0 {
        return Ok(());
    }

    let org_id = "123".to_string();
    let now = now_ms();

    conn.execute(
        "INSERT INTO orgs (id, name, tagline, logo_initial, theme_primary, theme_primary_dark,
            theme_accent, theme_accent_soft, theme_background, theme_surface,
            theme_text_primary, theme_text_secondary, theme_border, created_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
        params![
            org_id,
            "The Wayfarer",
            "Kitchen & Bar",
            "W",
            "#1F4D3E",
            "#123328",
            "#C9A15F",
            "#F3E9D2",
            "#FBF8F2",
            "#FFFFFF",
            "#20241F",
            "#71786D",
            "#E9E4D6",
            now,
        ],
    )?;

    // demo admin login: admin@wayfarer.test / wayfarer123
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password("wayfarer123".as_bytes(), &salt)
        .expect("hash demo password")
        .to_string();
    conn.execute(
        "INSERT INTO admin_users (id, org_id, name, email, password_hash, created_at) VALUES (?1,?2,?3,?4,?5,?6)",
        params![Uuid::new_v4().to_string(), org_id, "Demo Admin", "admin@wayfarer.test", hash, now],
    )?;

    let tables = [("Table 1", 2), ("Table 4", 4), ("Patio 2", 6)];
    let mut table_ids: Vec<String> = Vec::new();
    for (name, seats) in tables {
        let id = Uuid::new_v4().to_string();
        let qr = format!("{}?orgId={}&tableId={}", client_origin, org_id, id);
        conn.execute(
            "INSERT INTO tables (id, org_id, name, seats, qr_value, created_at) VALUES (?1,?2,?3,?4,?5,?6)",
            params![id, org_id, name, seats, qr, now],
        )?;
        table_ids.push(id);
    }

    let menu: [(&str, &str, &str, &str, &str, f64, &str); 6] = [
        (
            "starters",
            "Burrata & Heirloom Tomato",
            "Creamy burrata, heirloom tomatoes, basil oil, aged balsamic.",
            "",
            "",
            16.0,
            r#"["veg","popular"]"#,
        ),
        (
            "starters",
            "Soup of the Day",
            "Ask your server for today's selection.",
            "",
            "",
            11.0,
            r#"["veg"]"#,
        ),
        (
            "mains",
            "Grilled Ribeye",
            "14oz, chimichurri, triple-cooked fries.",
            "",
            "",
            46.0,
            r#"["popular"]"#,
        ),
        (
            "mains",
            "Wild Mushroom Risotto",
            "Truffle oil, aged parmesan, wild arugula.",
            "",
            "",
            24.0,
            r#"["veg"]"#,
        ),
        (
            "desserts",
            "Chocolate Fondant",
            "Vanilla bean ice cream, salted caramel.",
            "",
            "",
            12.0,
            r#"["popular"]"#,
        ),
        (
            "drinks",
            "Old Fashioned",
            "Bourbon, bitters, orange oil.",
            "",
            "",
            17.0,
            r#"["popular"]"#,
        ),
    ];
    let mut item_ids: Vec<(String, String, f64)> = Vec::new();
    for (i, (cat, name, desc, img, portion, price, tags)) in menu.iter().enumerate() {
        let id = Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO menu_items (id, org_id, category, name, description, image, portion, price, tags, sort_order)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8, ?9, ?10)",
            params![id, org_id, cat, name, desc, img, portion, price, tags, i as i64],
        )?;
        item_ids.push((id, name.to_string(), *price));
    }

    // one demo order already "preparing" on Table 4, so the tracking view
    // has something to show immediately
    let order_id = Uuid::new_v4().to_string();
    let subtotal = item_ids[0].2 + item_ids[2].2 * 2.0;
    let tax = subtotal * 0.08;
    conn.execute(
        "INSERT INTO orders (id, org_id, table_id, table_name, status, subtotal, tax, total, created_at, updated_at)
         VALUES (?1,?2,?3,?4,'preparing',?5,?6,?7,?8,?9)",
        params![order_id, org_id, table_ids[1], "Table 4", subtotal, tax, subtotal + tax, now - 9 * 60 * 1000, now],
    )?;
    conn.execute(
        "INSERT INTO order_items (id, order_id, menu_item_id, name, price, qty, note) VALUES (?1,?2,?3,?4,?5,1,'')",
        params![Uuid::new_v4().to_string(), order_id, item_ids[0].0, item_ids[0].1, item_ids[0].2],
    )?;
    conn.execute(
        "INSERT INTO order_items (id, order_id, menu_item_id, name, price, qty, note) VALUES (?1,?2,?3,?4,?5,2,'')",
        params![Uuid::new_v4().to_string(), order_id, item_ids[2].0, item_ids[2].1, item_ids[2].2],
    )?;

    Ok(())
}

// =========================================================================
// Auth: password hashing + JWT
// =========================================================================

fn hash_password(password: &str) -> Result<String, AppError> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)?
        .to_string())
}

fn verify_password(password: &str, hash: &str) -> Result<bool, AppError> {
    let parsed = PasswordHash::new(hash).map_err(|e| AppError::internal(e.to_string()))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String,    // admin_user id
    org_id: String, // == restaurant id
    exp: i64,
}

fn issue_token(user_id: &str, org_id: &str, secret: &str) -> Result<String, AppError> {
    let claims = Claims {
        sub: user_id.to_string(),
        org_id: org_id.to_string(),
        exp: (Utc::now() + chrono::Duration::days(7)).timestamp(),
    };
    let token = jsonwebtoken::encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )?;
    Ok(token)
}

fn verify_token(token: &str, secret: &str) -> Result<Claims, AppError> {
    let data = jsonwebtoken::decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )?;
    Ok(data.claims)
}

/// Extracts + verifies the `Authorization: Bearer <token>` header.
/// Use as a handler parameter to require admin auth on a route.
struct AuthUser {
    #[allow(dead_code)]
    user_id: String,
    org_id: String,
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    SharedState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let state = SharedState::from_ref(state);

        let header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| AppError::unauthorized("missing Authorization header"))?;

        let token = header
            .strip_prefix("Bearer ")
            .ok_or_else(|| AppError::unauthorized("expected 'Bearer <token>'"))?;

        let claims = verify_token(token, &state.jwt_secret)?;

        Ok(AuthUser {
            user_id: claims.sub,
            org_id: claims.org_id,
        })
    }
}
/// Ensures the authenticated admin belongs to the org in the URL path.
fn ensure_own_org(auth: &AuthUser, org_id: &str) -> Result<(), AppError> {
    if auth.org_id != org_id {
        return Err(AppError::forbidden(
            "you do not have access to this restaurant",
        ));
    }
    Ok(())
}

// =========================================================================
// Shared response models
// =========================================================================

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ThemeOut {
    primary: String,
    primary_dark: String,
    accent: String,
    accent_soft: String,
    background: String,
    surface: String,
    text_primary: String,
    text_secondary: String,
    border: String,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct OrgOut {
    id: String,
    name: String,
    tagline: String,
    logo_initial: String,
    theme: ThemeOut,
}

fn org_from_row(row: &Row) -> rusqlite::Result<OrgOut> {
    Ok(OrgOut {
        id: row.get("id")?,
        name: row.get("name")?,
        tagline: row.get("tagline")?,
        logo_initial: row.get("logo_initial")?,
        theme: ThemeOut {
            primary: row.get("theme_primary")?,
            primary_dark: row.get("theme_primary_dark")?,
            accent: row.get("theme_accent")?,
            accent_soft: row.get("theme_accent_soft")?,
            background: row.get("theme_background")?,
            surface: row.get("theme_surface")?,
            text_primary: row.get("theme_text_primary")?,
            text_secondary: row.get("theme_text_secondary")?,
            border: row.get("theme_border")?,
        },
    })
}

fn get_org(conn: &Connection, org_id: &str) -> rusqlite::Result<OrgOut> {
    conn.query_row(
        "SELECT * FROM orgs WHERE id = ?1",
        params![org_id],
        org_from_row,
    )
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TableOut {
    id: String,
    name: String,
    seats: i64,
    qr_value: String,
}

fn table_from_row(row: &Row) -> rusqlite::Result<TableOut> {
    Ok(TableOut {
        id: row.get("id")?,
        name: row.get("name")?,
        seats: row.get("seats")?,
        qr_value: row.get("qr_value")?,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MenuItemOut {
    id: String,
    category: String,
    name: String,
    description: String,
    image: String,
    portion: String,
    price: f64,
    tags: Vec<String>,
}

fn menu_item_from_row(row: &Row) -> rusqlite::Result<MenuItemOut> {
    let tags_json: String = row.get("tags")?;
    let tags: Vec<String> = serde_json::from_str(&tags_json).unwrap_or_default();
    Ok(MenuItemOut {
        id: row.get("id")?,
        category: row.get("category")?,
        name: row.get("name")?,
        description: row.get("description")?,
        image: row.get("image")?,
        portion: row.get("portion")?,
        price: row.get("price")?,
        tags,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OrderItemOut {
    id: String,
    name: String,
    price: f64,
    qty: i64,
    note: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OrderOut {
    id: String,
    table_id: String,
    table_name: String,
    status: String,
    subtotal: f64,
    tax: f64,
    total: f64,
    created_at: i64,
    updated_at: i64,
    items: Vec<OrderItemOut>,
}

fn load_order_items(conn: &Connection, order_id: &str) -> rusqlite::Result<Vec<OrderItemOut>> {
    let mut stmt =
        conn.prepare("SELECT id, name, price, qty, note FROM order_items WHERE order_id = ?1")?;
    let rows = stmt.query_map(params![order_id], |r| {
        Ok(OrderItemOut {
            id: r.get(0)?,
            name: r.get(1)?,
            price: r.get(2)?,
            qty: r.get(3)?,
            note: r.get(4)?,
        })
    })?;
    rows.collect()
}

fn order_from_row(conn: &Connection, row: &Row) -> rusqlite::Result<OrderOut> {
    let id: String = row.get("id")?;
    let items = load_order_items(conn, &id)?;
    Ok(OrderOut {
        id,
        table_id: row.get("table_id")?,
        table_name: row.get("table_name")?,
        status: row.get("status")?,
        subtotal: row.get("subtotal")?,
        tax: row.get("tax")?,
        total: row.get("total")?,
        created_at: row.get("created_at")?,
        updated_at: row.get("updated_at")?,
        items,
    })
}

fn get_order(conn: &Connection, org_id: &str, order_id: &str) -> rusqlite::Result<OrderOut> {
    conn.query_row(
        "SELECT * FROM orders WHERE id = ?1 AND org_id = ?2",
        params![order_id, org_id],
        |row| order_from_row(conn, row),
    )
}

fn broadcast_event(state: &SharedState, org_id: &str, event_type: &str, order: &OrderOut) {
    let payload = serde_json::json!({ "type": event_type, "order": order }).to_string();
    let _ = state.tx.send(BroadcastMsg {
        org_id: org_id.to_string(),
        payload,
    });
}

// =========================================================================
// Auth handlers
// =========================================================================

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterBody {
    org_name: String,
    name: String,
    email: String,
    password: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthResponse {
    token: String,
    org: OrgOut,
    user: UserOut,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UserOut {
    id: String,
    name: String,
    email: String,
}

async fn register(
    State(state): State<SharedState>,
    Json(body): Json<RegisterBody>,
) -> Result<Json<AuthResponse>, AppError> {
    if body.org_name.trim().is_empty() || body.email.trim().is_empty() || body.password.len() < 8 {
        return Err(AppError::bad_request(
            "orgName and email are required, and password must be at least 8 characters",
        ));
    }

    let password_hash = hash_password(&body.password)?;
    let org_id = Uuid::new_v4().to_string();
    let user_id = Uuid::new_v4().to_string();
    let logo_initial = body
        .org_name
        .chars()
        .next()
        .unwrap_or('R')
        .to_uppercase()
        .to_string();
    let email = body.email.trim().to_lowercase();
    let name = body.name.clone();
    let org_name = body.org_name.clone();

    let (org, user) = db_call(&state, move |conn| {
        let now = now_ms();
        conn.execute(
            "INSERT INTO orgs (id, name, tagline, logo_initial, theme_primary, theme_primary_dark,
                theme_accent, theme_accent_soft, theme_background, theme_surface,
                theme_text_primary, theme_text_secondary, theme_border, created_at)
             VALUES (?1,?2,'',?3,'#1F4D3E','#123328','#C9A15F','#F3E9D2','#FBF8F2','#FFFFFF','#20241F','#71786D','#E9E4D6',?4)",
            params![org_id, org_name, logo_initial, now],
        )?;
        conn.execute(
            "INSERT INTO admin_users (id, org_id, name, email, password_hash, created_at) VALUES (?1,?2,?3,?4,?5,?6)",
            params![user_id, org_id, name, email, password_hash, now],
        )?;
        let org = get_org(conn, &org_id)?;
        let user = UserOut { id: user_id.clone(), name: name.clone(), email: email.clone() };
        Ok((org, user))
    })
    .await
    .map_err(|e| {
        if e.message.contains("UNIQUE") {
            AppError::bad_request("an account with that email already exists")
        } else {
            e
        }
    })?;

    let token = issue_token(&user.id, &org.id, &state.jwt_secret)?;
    Ok(Json(AuthResponse { token, org, user }))
}

#[derive(Deserialize)]
struct LoginBody {
    email: String,
    password: String,
}

async fn login(
    State(state): State<SharedState>,
    Json(body): Json<LoginBody>,
) -> Result<Json<AuthResponse>, AppError> {
    let email = body.email.trim().to_lowercase();

    let row = db_call(&state, move |conn| {
        conn.query_row(
            "SELECT id, org_id, name, email, password_hash FROM admin_users WHERE email = ?1",
            params![email],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                ))
            },
        )
    })
    .await
    .map_err(|_| AppError::unauthorized("invalid email or password"))?;

    let (user_id, org_id, name, email, password_hash) = row;

    if !verify_password(&body.password, &password_hash)? {
        return Err(AppError::unauthorized("invalid email or password"));
    }

    let org = db_call(&state, move |conn| get_org(conn, &org_id)).await?;
    let token = issue_token(&user_id, &org.id, &state.jwt_secret)?;
    let user = UserOut {
        id: user_id,
        name,
        email,
    };
    Ok(Json(AuthResponse { token, org, user }))
}

async fn me(
    State(state): State<SharedState>,
    auth: AuthUser,
) -> Result<Json<AuthResponse>, AppError> {
    let org_id = auth.org_id.clone();
    let org = db_call(&state, move |conn| get_org(conn, &org_id)).await?;

    let user_id = auth.user_id.clone();
    let user = db_call(&state, move |conn| {
        conn.query_row(
            "SELECT id, name, email FROM admin_users WHERE id = ?1",
            params![user_id],
            |r| {
                Ok(UserOut {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    email: r.get(2)?,
                })
            },
        )
    })
    .await?;

    // no fresh credentials to re-sign with here; reissue against the same
    // claims purely so the response shape matches register/login.
    let token = issue_token(&user.id, &org.id, &state.jwt_secret)?;
    Ok(Json(AuthResponse { token, org, user }))
}

// =========================================================================
// Org handlers
// =========================================================================

async fn get_org_handler(
    State(state): State<SharedState>,
    Path(org_id): Path<String>,
) -> Result<Json<OrgOut>, AppError> {
    let org = db_call(&state, move |conn| get_org(conn, &org_id)).await?;
    Ok(Json(org))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateOrgBody {
    name: Option<String>,
    tagline: Option<String>,
    logo_initial: Option<String>,
    theme: Option<ThemeIn>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ThemeIn {
    primary: String,
    primary_dark: String,
    accent: String,
    accent_soft: String,
    background: String,
    surface: String,
    text_primary: String,
    text_secondary: String,
    border: String,
}

async fn update_org(
    State(state): State<SharedState>,
    Path(org_id): Path<String>,
    auth: AuthUser,
    Json(body): Json<UpdateOrgBody>,
) -> Result<Json<OrgOut>, AppError> {
    ensure_own_org(&auth, &org_id)?;

    db_call(&state, move |conn| {
        let current = get_org(conn, &org_id)?;
        let name = body.name.unwrap_or(current.name);
        let tagline = body.tagline.unwrap_or(current.tagline);
        let logo_initial = body.logo_initial.unwrap_or(current.logo_initial);
        let theme = body
            .theme
            .map(|t| ThemeOut {
                primary: t.primary,
                primary_dark: t.primary_dark,
                accent: t.accent,
                accent_soft: t.accent_soft,
                background: t.background,
                surface: t.surface,
                text_primary: t.text_primary,
                text_secondary: t.text_secondary,
                border: t.border,
            })
            .unwrap_or(current.theme);

        conn.execute(
            "UPDATE orgs SET name=?1, tagline=?2, logo_initial=?3, theme_primary=?4, theme_primary_dark=?5,
                theme_accent=?6, theme_accent_soft=?7, theme_background=?8, theme_surface=?9,
                theme_text_primary=?10, theme_text_secondary=?11, theme_border=?12 WHERE id=?13",
            params![name, tagline, logo_initial, theme.primary, theme.primary_dark, theme.accent,
                theme.accent_soft, theme.background, theme.surface, theme.text_primary,
                theme.text_secondary, theme.border, org_id],
        )?;
        get_org(conn, &org_id)
    })
    .await
    .map(Json)
}

// =========================================================================
// Table handlers
// =========================================================================

async fn list_tables(
    State(state): State<SharedState>,
    Path(org_id): Path<String>,
    auth: AuthUser,
) -> Result<Json<Vec<TableOut>>, AppError> {
    ensure_own_org(&auth, &org_id)?;
    let tables = db_call(&state, move |conn| {
        let mut stmt =
            conn.prepare("SELECT * FROM tables WHERE org_id = ?1 ORDER BY created_at ASC")?;
        let rows = stmt.query_map(params![org_id], table_from_row)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
    })
    .await?;
    Ok(Json(tables))
}

async fn get_table_handler(
    State(state): State<SharedState>,
    Path((org_id, table_id)): Path<(String, String)>,
) -> Result<Json<TableOut>, AppError> {
    let table = db_call(&state, move |conn| {
        conn.query_row(
            "SELECT * FROM tables WHERE org_id = ?1 AND id = ?2",
            params![org_id, table_id],
            table_from_row,
        )
    })
    .await?;
    Ok(Json(table))
}

#[derive(Deserialize)]
struct CreateTableBody {
    name: String,
    seats: i64,
}

async fn create_table(
    State(state): State<SharedState>,
    Path(org_id): Path<String>,
    auth: AuthUser,
    Json(body): Json<CreateTableBody>,
) -> Result<Json<TableOut>, AppError> {
    ensure_own_org(&auth, &org_id)?;
    if body.name.trim().is_empty() {
        return Err(AppError::bad_request("table name is required"));
    }

    let _client_origin = state.client_origin.clone();
    let table = db_call(&state, move |conn| {
        let id = Uuid::new_v4().to_string();
        let qr_value = format!("{}?orgId={}&tableId={}", "https://sidx2.github.io/rexus-client/", org_id, id);
        conn.execute(
            "INSERT INTO tables (id, org_id, name, seats, qr_value, created_at) VALUES (?1,?2,?3,?4,?5,?6)",
            params![id, org_id, body.name.trim(), body.seats.max(1), qr_value, now_ms()],
        )?;
        conn.query_row("SELECT * FROM tables WHERE id = ?1", params![id], table_from_row)
    })
    .await?;
    Ok(Json(table))
}

#[derive(Deserialize)]
struct UpdateTableBody {
    name: Option<String>,
    seats: Option<i64>,
}

async fn update_table(
    State(state): State<SharedState>,
    Path((org_id, table_id)): Path<(String, String)>,
    auth: AuthUser,
    Json(body): Json<UpdateTableBody>,
) -> Result<Json<TableOut>, AppError> {
    ensure_own_org(&auth, &org_id)?;

    let table = db_call(&state, move |conn| {
        let current = conn.query_row(
            "SELECT * FROM tables WHERE org_id = ?1 AND id = ?2",
            params![org_id, table_id],
            table_from_row,
        )?;
        let name = body.name.unwrap_or(current.name);
        let seats = body.seats.unwrap_or(current.seats);
        conn.execute(
            "UPDATE tables SET name = ?1, seats = ?2 WHERE id = ?3",
            params![name, seats, table_id],
        )?;
        conn.query_row(
            "SELECT * FROM tables WHERE id = ?1",
            params![table_id],
            table_from_row,
        )
    })
    .await?;
    Ok(Json(table))
}

async fn delete_table(
    State(state): State<SharedState>,
    Path((org_id, table_id)): Path<(String, String)>,
    auth: AuthUser,
) -> Result<StatusCode, AppError> {
    ensure_own_org(&auth, &org_id)?;
    db_call(&state, move |conn| {
        conn.execute(
            "DELETE FROM tables WHERE org_id = ?1 AND id = ?2",
            params![org_id, table_id],
        )
    })
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

// =========================================================================
// Menu handlers
// =========================================================================

async fn get_menu(
    State(state): State<SharedState>,
    Path(org_id): Path<String>,
) -> Result<Json<Vec<MenuItemOut>>, AppError> {
    let items = db_call(&state, move |conn| {
        let mut stmt =
            conn.prepare("SELECT * FROM menu_items WHERE org_id = ?1 ORDER BY sort_order ASC")?;
        let rows = stmt.query_map(params![org_id], menu_item_from_row)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
    })
    .await?;
    Ok(Json(items))
}

#[derive(Deserialize)]
struct MenuItemIn {
    id: Option<String>,
    category: String,
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    image: String,
    #[serde(default)]
    portion: String,
    price: f64,
    #[serde(default)]
    tags: Vec<String>,
}

/// Bulk replace — matches the frontend's `saveMenu(restaurantId, items)`
/// contract, which sends the *entire* menu and expects a boolean back.
async fn save_menu(
    State(state): State<SharedState>,
    Path(org_id): Path<String>,
    auth: AuthUser,
    Json(items): Json<Vec<MenuItemIn>>,
) -> Result<Json<serde_json::Value>, AppError> {
    ensure_own_org(&auth, &org_id)?;

    db_call(&state, move |conn| {
        let tx = conn.unchecked_transaction()?;
        tx.execute("DELETE FROM menu_items WHERE org_id = ?1", params![org_id])?;
        for (i, item) in items.into_iter().enumerate() {
            let id = item.id.unwrap_or_else(|| Uuid::new_v4().to_string());
            let tags_json = serde_json::to_string(&item.tags).unwrap_or_else(|_| "[]".to_string());
            tx.execute(
                "INSERT INTO menu_items (id, org_id, category, name, description, image, portion, price, tags, sort_order)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                params![id, org_id, item.category, item.name, item.description, item.image, item.portion, item.price, tags_json, i as i64],
            )?;
        }
        tx.commit()
    })
    .await?;

    Ok(Json(serde_json::json!({ "success": true })))
}

async fn create_menu_item(
    State(state): State<SharedState>,
    Path(org_id): Path<String>,
    auth: AuthUser,
    Json(item): Json<MenuItemIn>,
) -> Result<Json<MenuItemOut>, AppError> {
    ensure_own_org(&auth, &org_id)?;

    let created = db_call(&state, move |conn| {
        let id = item.id.unwrap_or_else(|| Uuid::new_v4().to_string());
        let tags_json = serde_json::to_string(&item.tags).unwrap_or_else(|_| "[]".to_string());
        let next_sort: i64 = conn.query_row(
            "SELECT COALESCE(MAX(sort_order), -1) + 1 FROM menu_items WHERE org_id = ?1",
            params![org_id],
            |r| r.get(0),
        )?;
        conn.execute(
            "INSERT INTO menu_items (id, org_id, category, name, description, image, portion, price, tags, sort_order)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![id, org_id, item.category, item.name, item.description, item.image, item.portion, item.price, tags_json, next_sort],
        )?;
        conn.query_row("SELECT * FROM menu_items WHERE id = ?1", params![id], menu_item_from_row)
    })
    .await?;
    Ok(Json(created))
}

async fn update_menu_item(
    State(state): State<SharedState>,
    Path((org_id, item_id)): Path<(String, String)>,
    auth: AuthUser,
    Json(item): Json<MenuItemIn>,
) -> Result<Json<MenuItemOut>, AppError> {
    ensure_own_org(&auth, &org_id)?;

    let updated = db_call(&state, move |conn| {
        let tags_json = serde_json::to_string(&item.tags).unwrap_or_else(|_| "[]".to_string());
        conn.execute(
            "UPDATE menu_items SET category=?1, name=?2, description=?3, image=?4, portion=?5, price=?6, tags=?7
            WHERE id=?8 AND org_id=?9",
            params![
                item.category,
                item.name,
                item.description,
                item.image,
                item.portion,
                item.price,
                tags_json,
                item_id,
                org_id
            ],
        )?;
        conn.query_row(
            "SELECT * FROM menu_items WHERE id = ?1",
            params![item_id],
            menu_item_from_row,
        )
    })
    .await?;
    Ok(Json(updated))
}

async fn delete_menu_item(
    State(state): State<SharedState>,
    Path((org_id, item_id)): Path<(String, String)>,
    auth: AuthUser,
) -> Result<StatusCode, AppError> {
    ensure_own_org(&auth, &org_id)?;
    db_call(&state, move |conn| {
        conn.execute(
            "DELETE FROM menu_items WHERE org_id = ?1 AND id = ?2",
            params![org_id, item_id],
        )
    })
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

// =========================================================================
// Order handlers
// =========================================================================

const TAX_RATE: f64 = 0.08;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PlaceOrderItem {
    item_id: Option<String>,
    name: String,
    price: f64,
    qty: i64,
    #[serde(default)]
    note: String,
}

#[derive(Deserialize)]
struct PlaceOrderBody {
    items: Vec<PlaceOrderItem>,
}

/// Guest places an order for a table. Prices are re-looked-up from the
/// menu by id when possible (client-sent price is only a fallback for
/// custom/off-menu lines) so a guest can't tamper with totals.
async fn place_order(
    State(state): State<SharedState>,
    Path((org_id, table_id)): Path<(String, String)>,
    Json(body): Json<PlaceOrderBody>,
) -> Result<Json<OrderOut>, AppError> {
    if body.items.is_empty() {
        return Err(AppError::bad_request(
            "order must contain at least one item",
        ));
    }

    let org_id_for_broadcast = org_id.clone();

    let order = db_call(&state, move |conn| {
        let table_name: String = conn.query_row(
            "SELECT name FROM tables WHERE org_id = ?1 AND id = ?2",
            params![org_id, table_id],
            |r| r.get(0),
        )?;

        let mut subtotal = 0.0;
        let mut resolved_items: Vec<(Option<String>, String, f64, i64, String)> = Vec::new();
        for line in &body.items {
            if line.qty <= 0 {
                continue;
            }
            let price = if let Some(item_id) = &line.item_id {
                conn.query_row(
                    "SELECT price FROM menu_items WHERE id = ?1 AND org_id = ?2",
                    params![item_id, org_id],
                    |r| r.get::<_, f64>(0),
                )
                .unwrap_or(line.price)
            } else {
                line.price
            };
            subtotal += price * line.qty as f64;
            resolved_items.push((line.item_id.clone(), line.name.clone(), price, line.qty, line.note.clone()));
        }

        if resolved_items.is_empty() {
            return Err(rusqlite::Error::InvalidQuery);
        }

        let tax = subtotal * TAX_RATE;
        let total = subtotal + tax;
        let order_id = Uuid::new_v4().to_string();
        let now = now_ms();

        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO orders (id, org_id, table_id, table_name, status, subtotal, tax, total, created_at, updated_at)
             VALUES (?1,?2,?3,?4,'new',?5,?6,?7,?8,?9)",
            params![order_id, org_id, table_id, table_name, subtotal, tax, total, now, now],
        )?;
        for (menu_item_id, name, price, qty, note) in &resolved_items {
            tx.execute(
                "INSERT INTO order_items (id, order_id, menu_item_id, name, price, qty, note) VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![Uuid::new_v4().to_string(), order_id, menu_item_id, name, price, qty, note],
            )?;
        }
        tx.commit()?;

        get_order(conn, &org_id, &order_id)
    })
    .await?;

    broadcast_event(&state, &org_id_for_broadcast, "order:new", &order);
    Ok(Json(order))
}

#[derive(Deserialize)]
struct PendingQuery {
    status: Option<String>,
}

/// Guest-facing: orders for a specific table, "today" implicitly (guests
/// only ever care about their current visit).
async fn table_orders(
    State(state): State<SharedState>,
    Path((org_id, table_id)): Path<(String, String)>,
    Query(q): Query<PendingQuery>,
) -> Result<Json<Vec<OrderOut>>, AppError> {
    let pending_only = q.status.as_deref() == Some("pending");

    let orders = db_call(&state, move |conn| {
        let sql = if pending_only {
            "SELECT id FROM orders WHERE org_id = ?1 AND table_id = ?2 AND status != 'served' ORDER BY created_at DESC"
        } else {
            "SELECT id FROM orders WHERE org_id = ?1 AND table_id = ?2 ORDER BY created_at DESC"
        };
        let mut stmt = conn.prepare(sql)?;
        let ids: Vec<String> = stmt
            .query_map(params![org_id, table_id], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<_>>()?;
        ids.into_iter()
            .map(|id| get_order(conn, &org_id, &id))
            .collect::<rusqlite::Result<Vec<_>>>()
    })
    .await?;
    Ok(Json(orders))
}

#[derive(Deserialize)]
struct AdminOrdersQuery {
    #[allow(dead_code)]
    scope: Option<String>, // "today" (default) if no from/to given
    from: Option<String>, // RFC3339
    to: Option<String>,   // RFC3339
    status: Option<String>,
}

/// Admin REST listing — used for the "today" fallback and for the
/// arbitrary-range `fetchPastOrders(from, to)` query from the dashboard.
async fn list_org_orders(
    State(state): State<SharedState>,
    Path(org_id): Path<String>,
    auth: AuthUser,
    Query(q): Query<AdminOrdersQuery>,
) -> Result<Json<Vec<OrderOut>>, AppError> {
    ensure_own_org(&auth, &org_id)?;

    let (from_ms, to_ms) = resolve_range(&q)?;
    let status = q.status.clone();

    let orders = db_call(&state, move |conn| {
        let mut sql = String::from(
            "SELECT id FROM orders WHERE org_id = ?1 AND created_at >= ?2 AND created_at <= ?3",
        );
        if status.is_some() {
            sql.push_str(" AND status = ?4");
        }
        sql.push_str(" ORDER BY created_at DESC");

        let mut stmt = conn.prepare(&sql)?;
        let ids: Vec<String> = if let Some(s) = &status {
            stmt.query_map(params![org_id, from_ms, to_ms, s], |r| {
                r.get::<_, String>(0)
            })?
            .collect::<rusqlite::Result<_>>()?
        } else {
            stmt.query_map(params![org_id, from_ms, to_ms], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<_>>()?
        };
        ids.into_iter()
            .map(|id| get_order(conn, &org_id, &id))
            .collect::<rusqlite::Result<Vec<_>>>()
    })
    .await?;
    Ok(Json(orders))
}

fn resolve_range(q: &AdminOrdersQuery) -> Result<(i64, i64), AppError> {
    if let (Some(from), Some(to)) = (&q.from, &q.to) {
        let from_ms = DateTime::parse_from_rfc3339(from)
            .map_err(|_| AppError::bad_request("`from` must be RFC3339"))?
            .timestamp_millis();
        let to_ms = DateTime::parse_from_rfc3339(to)
            .map_err(|_| AppError::bad_request("`to` must be RFC3339"))?
            .timestamp_millis();
        return Ok((from_ms, to_ms));
    }
    // default / "today": midnight UTC today -> now
    let now = Utc::now();
    let start = now
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .unwrap()
        .and_utc()
        .timestamp_millis();
    Ok((start, now.timestamp_millis()))
}

#[derive(Deserialize)]
struct UpdateStatusBody {
    status: String,
}

const VALID_STATUSES: [&str; 4] = ["new", "preparing", "ready", "served"];

async fn update_order_status(
    State(state): State<SharedState>,
    Path((org_id, order_id)): Path<(String, String)>,
    auth: AuthUser,
    Json(body): Json<UpdateStatusBody>,
) -> Result<Json<OrderOut>, AppError> {
    ensure_own_org(&auth, &org_id)?;
    if !VALID_STATUSES.contains(&body.status.as_str()) {
        return Err(AppError::bad_request(
            "status must be one of new, preparing, ready, served",
        ));
    }

    let org_id_for_broadcast = org_id.clone();
    let order = db_call(&state, move |conn| {
        conn.execute(
            "UPDATE orders SET status = ?1, updated_at = ?2 WHERE id = ?3 AND org_id = ?4",
            params![body.status, now_ms(), order_id, org_id],
        )?;
        get_order(conn, &org_id, &order_id)
    })
    .await?;

    broadcast_event(&state, &org_id_for_broadcast, "order:update", &order);
    Ok(Json(order))
}

// =========================================================================
// WebSocket — real-time order feed for the admin dashboard
// =========================================================================

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WsQuery {
    org_id: String,
    token: String,
}

async fn ws_orders(
    ws: WebSocketUpgrade,
    State(state): State<SharedState>,
    Query(q): Query<WsQuery>,
) -> Result<Response, AppError> {
    // Auth happens before the upgrade so a bad token gets a clean HTTP 401
    // instead of an opened-then-immediately-closed socket.
    let claims = verify_token(&q.token, &state.jwt_secret)?;
    if claims.org_id != q.org_id {
        return Err(AppError::forbidden("token does not match orgId"));
    }

    Ok(ws.on_upgrade(move |socket| handle_socket(socket, state, q.org_id)))
}

async fn handle_socket(mut socket: WebSocket, state: SharedState, org_id: String) {
    println!("WS CONNECTED org={}", org_id);

    let mut broadcast_rx = state.tx.subscribe();

    loop {
        tokio::select! {
                    incoming = socket.recv() => {
                        match incoming {
                            Some(Ok(Message::Text(text))) => {
                                if handle_client_message(&mut socket, &state, &org_id, &text).await.is_err() {
                                    break;
                                }
                            }
                            Some(Ok(Message::Close(frame))) => {
                                println!(
                                    "🔴 WS CLOSE org={} frame={:?}",
                                    org_id,
                                    frame
                                );
                                break;
                            },
                            Some(Err(_)) => break,
                            _ => {}
                        }
                    }
                    msg = broadcast_rx.recv() => {
                        match msg {
                            Ok(bmsg) if bmsg.org_id == org_id => {
                                if socket.send(Message::Text(bmsg.payload)).await.is_err() {
                                    break;
                                }
                            }
                            Ok(_) => {} // different org, ignore
                            Err(broadcast::error::RecvError::Lagged(_)) => {} // dropped some msgs, keep going
                            Err(broadcast::error::RecvError::Closed) => break,
                        }
                    }
                }
    }
}

async fn handle_client_message(
    socket: &mut WebSocket,
    state: &SharedState,
    org_id: &str,
    text: &str,
) -> Result<(), axum::Error> {
    let Ok(msg): Result<serde_json::Value, _> = serde_json::from_str(text) else {
        return Ok(());
    };
    let msg_type = msg.get("type").and_then(|v| v.as_str()).unwrap_or("");

    match msg_type {
        "orders:subscribe" => {
            let org_id_owned = org_id.to_string();
            let orders = db_call(state, move |conn| {
                let start = Utc::now().date_naive().and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp_millis();
                let mut stmt = conn.prepare(
                    "SELECT id FROM orders WHERE org_id = ?1 AND created_at >= ?2 ORDER BY created_at DESC",
                )?;
                let ids: Vec<String> = stmt
                    .query_map(params![org_id_owned, start], |r| r.get::<_, String>(0))?
                    .collect::<rusqlite::Result<_>>()?;
                ids.into_iter()
                    .map(|id| get_order(conn, &org_id_owned, &id))
                    .collect::<rusqlite::Result<Vec<_>>>()
            })
            .await
            .unwrap_or_default();

            let payload =
                serde_json::json!({ "type": "orders:sync", "orders": orders }).to_string();
            socket.send(Message::Text(payload)).await?;
        }
        "order:updateStatus" => {
            let order_id = msg
                .get("orderId")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let status = msg
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if order_id.is_empty() || !VALID_STATUSES.contains(&status.as_str()) {
                return Ok(());
            }
            let org_id_owned = org_id.to_string();
            let org_id_for_broadcast = org_id_owned.clone();
            let updated = db_call(state, move |conn| {
                conn.execute(
                    "UPDATE orders SET status = ?1, updated_at = ?2 WHERE id = ?3 AND org_id = ?4",
                    params![status, now_ms(), order_id, org_id_owned],
                )?;
                get_order(conn, &org_id_owned, &order_id)
            })
            .await;
            if let Ok(order) = updated {
                let payload =
                    serde_json::json!({ "type": "order:update", "order": order }).to_string();
                let _ = state.tx.send(BroadcastMsg {
                    org_id: org_id_for_broadcast,
                    payload,
                });
            }
        }
        "order:new" => {
            println!("order:new {msg}");
            let payload = serde_json::json!({
                "type": "order:new",
                "order": msg.get("order")
            })
            .to_string();

            let _ = state.tx.send(BroadcastMsg {
                org_id: org_id.to_string(),
                payload,
            });
        }
        _ => {}
    }
    Ok(())
}

// =========================================================================
// Router + main
// =========================================================================

async fn health() -> &'static str {
    "ok"
}

fn build_router(state: SharedState) -> Router {
    Router::new()
        .route("/health", get(health))
        // --- auth ---
        .route("/api/auth/register", post(register))
        .route("/api/auth/login", post(login))
        .route("/api/auth/me", get(me))
        // --- org ---
        .route("/api/orgs/:org_id", get(get_org_handler).put(update_org))
        // --- tables ---
        .route(
            "/api/orgs/:org_id/tables",
            get(list_tables).post(create_table),
        )
        .route(
            "/api/orgs/:org_id/tables/:table_id",
            get(get_table_handler)
                .put(update_table)
                .delete(delete_table),
        )
        // --- menu ---
        .route("/api/orgs/:org_id/menu", get(get_menu).put(save_menu))
        .route("/api/orgs/:org_id/menu/items", post(create_menu_item))
        .route(
            "/api/orgs/:org_id/menu/items/:item_id",
            put(update_menu_item).delete(delete_menu_item),
        )
        // --- orders ---
        .route(
            "/api/orgs/:org_id/tables/:table_id/orders",
            post(place_order).get(table_orders),
        )
        .route("/api/orgs/:org_id/orders", get(list_org_orders))
        .route(
            "/api/orgs/:org_id/orders/:order_id/status",
            patch(update_order_status),
        )
        // --- realtime ---
        .route("/ws/orders", get(ws_orders))
        .layer(CorsLayer::permissive()) // tighten to your real origins in production
        .with_state(state)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let db_path = std::env::var("DATABASE_PATH").unwrap_or_else(|_| "hotel.db".to_string());
    let client_origin =
        std::env::var("CLIENT_ORIGIN").unwrap_or_else(|_| "*".to_string());
    let jwt_secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| {
        tracing::warn!("JWT_SECRET not set — using an insecure default. Set it in production!");
        "dev-secret-change-me".to_string()
    });
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    let conn = Connection::open(&db_path).expect("open sqlite db");
    init_db(&conn).expect("init schema");
    seed_demo_data(&conn, &client_origin).expect("seed demo data");

    let (tx, _rx) = broadcast::channel::<BroadcastMsg>(256);

    let state: SharedState = Arc::new(AppState {
        db: Arc::new(Mutex::new(conn)),
        tx,
        jwt_secret,
        client_origin,
    });

    let app = build_router(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("bind port");
    axum::serve(listener, app).await.expect("server error");
}
