use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Extension, Multipart, Path, Request},
    http::StatusCode,
    middleware::Next,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use regex::Regex;
use serde_json::json;
use std::collections::HashSet;
use std::env;
use std::error::Error;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::{fs, io::AsyncWriteExt, process::Command};
use tower_http::{
    services::ServeDir,
    cors::CorsLayer,
};
use uuid::Uuid;

#[derive(Clone)]
struct Config {
    port: String,
    public_path: PathBuf,
    work_path: PathBuf,
    otaprov_path: PathBuf,
    key_path: PathBuf,
    valid_udids: HashSet<String>,
}

fn get_env_paths() -> Result<Config, String> {
    let port = env::var("PORT").map_err(|_| "PORT not set")?;
    let public_path = env::var("PUBLIC_PATH").map_err(|_| "PUBLIC_PATH not set")?;
    let work_path = env::var("WORK_PATH").map_err(|_| "WORK_PATH not set")?;
    let otaprov_path = env::var("OTAPROV_PATH").map_err(|_| "OTAPROV_PATH not set")?;
    let key_path = env::var("KEY_PATH").map_err(|_| "KEY_PATH not set")?;
    let udid_env = env::var("VALID_UDIDS").map_err(|_| "VALID_UDIDS not set")?;

    let valid_udids: HashSet<String> = udid_env
        .split(',')
        .map(|udid| udid.trim().to_uppercase())
        .filter(|udid| !udid.is_empty())
        .collect();

    if valid_udids.is_empty() {
        return Err("No valid UDIDs found. Please define VALID_UDIDS.".to_string());
    }

    Ok(Config {
        port,
        public_path: PathBuf::from(public_path),
        work_path: PathBuf::from(work_path),
        otaprov_path: PathBuf::from(otaprov_path),
        key_path: PathBuf::from(key_path),
        valid_udids,
    })
}

struct SignResult {
    bundle_id: String,
    bundle_ver: String,
}

async fn sign_ipa(
    input_ipa: &PathBuf,
    output_ipa: &PathBuf,
    ota_prov: &PathBuf,
    key: &PathBuf,
) -> Result<SignResult, Box<dyn Error>> {
    if !input_ipa.is_file() {
        return Err(format!("The input IPA file does not exist: {}", input_ipa.display()).into());
    }

    let output = Command::new("/zsign")
        .arg("-m")
        .arg(ota_prov.as_os_str())
        .arg("-k")
        .arg(key.as_os_str())
        .arg("-o")
        .arg(output_ipa.as_os_str())
        .arg(input_ipa)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined_output = if !stderr.is_empty() {
        format!("{}\n{}", stdout, stderr)
    } else {
        stdout.to_string()
    };

    if !combined_output.contains("Signed OK!") {
        return Err("Sign error".into());
    }

    let re_bundle_id = Regex::new(r"BundleId:\s*(\S+)").unwrap();
    let re_bundle_ver = Regex::new(r"BundleVer:\s*(\S+)").unwrap();

    let bundle_id = re_bundle_id
        .captures(&combined_output)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_string()))
        .ok_or("Missing BundleId")?;

    let bundle_ver = re_bundle_ver
        .captures(&combined_output)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_string()))
        .ok_or("Missing BundleVer")?;

    Ok(SignResult {
        bundle_id,
        bundle_ver,
    })
}

async fn inject_base_url(mut req: Request, next: Next) -> Response {
    let headers = req.headers();

    let host = match headers.get("host").and_then(|h| h.to_str().ok()) {
        Some(h) => h,
        None => {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(axum::body::Body::from("Missing Host header"))
                .unwrap();
        }
    };

    let protocol = if headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("http")
        == "https"
    {
        "https"
    } else {
        "http"
    };

    let base_url = format!("{}://{}", protocol, host);
    req.extensions_mut().insert(base_url);
    next.run(req).await
}

fn escape_xml(unsafe_str: &str) -> String {
    unsafe_str
        .chars()
        .map(|c| match c {
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '&' => "&amp;".to_string(),
            '\'' => "&apos;".to_string(),
            '"' => "&quot;".to_string(),
            _ => c.to_string(),
        })
        .collect()
}

async fn ota_handler(
    Extension(base_url): Extension<String>,
    Path((bundle_id, bundle_version, ipa_file_name)): Path<(String, String, String)>,
) -> impl IntoResponse {
    let ipa_url = format!("{}/public/{}", base_url, ipa_file_name);

    let plist_template = r#"<?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
    <key>items</key>
    <array>
    <dict>
    <key>assets</key>
    <array>
    <dict>
    <key>kind</key>
    <string>software-package</string>
    <key>url</key>
    <string>__IPA_URL__</string>
    </dict>
    </array>
    <key>metadata</key>
    <dict>
    <key>bundle-identifier</key>
    <string>__BUNDLE_IDENTIFIER__</string>
    <key>bundle-version</key>
    <string>__BUNDLE_VERSION__</string>
    <key>kind</key>
    <string>software</string>
    <key>title</key>
    <string>__APP_TITLE__</string>
    </dict>
    </dict>
    </array>
    </dict>
    </plist>"#;

    let mut plist_content = plist_template.to_string();

    let replacements = vec![
        ("__IPA_URL__", escape_xml(&ipa_url)),
        ("__BUNDLE_IDENTIFIER__", escape_xml(&bundle_id)),
        ("__BUNDLE_VERSION__", escape_xml(&bundle_version)),
        ("__APP_TITLE__", escape_xml(&bundle_id)),
    ];

    for (placeholder, value) in replacements {
        plist_content = plist_content.replace(placeholder, &value);
    }

    ([("Content-Type", "application/xml")], plist_content)
}

async fn install_handler(
    Extension(base_url): Extension<String>,
    Path((bundle_id, bundle_version, ipa_file_name)): Path<(String, String, String)>,
    req: Request,
) -> impl IntoResponse {
    if bundle_id.is_empty() || bundle_version.is_empty() || ipa_file_name.is_empty() {
        return (StatusCode::BAD_REQUEST, "Missing required parameters.").into_response();
    }

    let encoded_bundle_id = utf8_percent_encode(&bundle_id, NON_ALPHANUMERIC).to_string();
    let encoded_bundle_version = utf8_percent_encode(&bundle_version, NON_ALPHANUMERIC).to_string();
    let encoded_ipa_file_name = utf8_percent_encode(&ipa_file_name, NON_ALPHANUMERIC).to_string();

    let original_url = format!(
        "{}/install/{}/{}/{}",
        base_url, encoded_bundle_id, encoded_bundle_version, encoded_ipa_file_name
    );
    let mut target_url = format!(
        "itms-services://?action=download-manifest&url={}/ota/{}/{}/{}",
        base_url, encoded_bundle_id, encoded_bundle_version, encoded_ipa_file_name
    );

    let ua = req
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !ua.contains("iPhone")
        && !ua.contains("iPad")
        && !ua.contains("iPod")
        && !ua.contains("AppleWatch")
        && !ua.contains("Vision")
    {
        let qr_html = format!(
            r#"<strong>Scan this QR code with the iOS Camera app to install the IPA</strong>
            <div id="qrCode"></div>
            <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
            <script>
                new QRCode(document.getElementById("qrCode"), {{
                text: "{}",
                width: 200,
                height: 200,
                colorDark: "\#000000",
                colorLight: "\#ffffff",
                correctLevel: QRCode.CorrectLevel.M
            }});
            </script>"#,
            original_url
        );
        return Html(qr_html).into_response();
    } else if ua.contains("CriOS")
        || ua.contains("FxiOS")
        || ua.contains("EdgiOS")
        || ua.contains("OPiOS")
        || ua.contains("YaBrowser")
        || ua.contains("DuckDuckGo")
    {
        target_url = format!("x-safari-{}", original_url);
    }

    Redirect::temporary(&target_url).into_response()
}

async fn sign_handler(
    Extension(config): Extension<Config>,
    Extension(base_url): Extension<String>,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let mut udid = None;
    let mut file_bytes = None;
    let mut original_filename = None;

    while let Some(field) = multipart.next_field().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "message": format!("Error reading multipart field: {}", e) })),
        )
    })? {
        let name = field.name().map(|n| n.to_string()).ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "message": format!("Multipart field without name") })),
            )
        })?;

        if name == "udid" {
            let text = field.text().await.map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "message": format!("Error reading udid field: {}", e) })),
                )
            })?;

            udid = Some(text.trim().to_uppercase());
        } else if name == "file" {
            if let Some(filename) = field.file_name() {
                original_filename = Some(filename.to_string());
            }

            let bytes = field.bytes().await.map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "message": format!("Error reading file field: {}", e) })),
                )
            })?;
            file_bytes = Some(bytes);
        }
    }

    let udid = match udid {
        Some(u) => u,
        None => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "message": format!("Device UDID is missing.") })),
            ));
        }
    };

    if !config.valid_udids.contains(&udid) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "message": "Unauthorized UDID." })),
        ));
    }

    let file_bytes = match file_bytes {
        Some(f) => f,
        None => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({ "message": "No file uploaded." })),
            ));
        }
    };

    let original_filename = match original_filename {
        Some(f) => f,
        None => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({ "message": "No file uploaded." })),
            ));
        }
    };

    let sanitized_file_name =
        original_filename.replace(|c: char| !c.is_alphanumeric() && c != '-' && c != '_', "_");

    let uuid = Uuid::new_v4();
    let timestamp = chrono::Utc::now().timestamp_millis();
    let ipa_name = format!(
        "{}_{}_{}_{}.ipa",
        timestamp, uuid, udid, sanitized_file_name
    );
    let work_ipa_path = config.work_path.join(&ipa_name);
    let output_ipa_path = config.public_path.join(&ipa_name);

    let mut file = fs::File::create(&work_ipa_path).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "message": format!("Unable to save IPA in the server: {}", e) })),
        )
    })?;

    file.write_all(&file_bytes).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "message": format!("Unable to save IPA in the server: {}", e) })),
        )
    })?;

    let sign_result = sign_ipa(
        &work_ipa_path,
        &output_ipa_path,
        &config.otaprov_path,
        &config.key_path,
    )
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "message": format!("Unable to sign IPA: {}", e) })),
        )
    })?;

    // Clean up work IPA file
    if let Err(e) = fs::remove_file(&work_ipa_path).await {
        eprintln!("Error deleting work IPA file: {}", e);
    }

    Ok((
        StatusCode::OK,
        Json(json!({
            "message": "IPA signed successfully.",
            "ipa_url": format!("{}/public/{}", base_url, ipa_name),
            "ota_url": format!("{}/ota/{}/{}/{}", base_url, sign_result.bundle_id, sign_result.bundle_ver, ipa_name),
            "install_url": format!("{}/install/{}/{}/{}", base_url, sign_result.bundle_id, sign_result.bundle_ver, ipa_name)
        })),
    ))
}

async fn clean_directories(public_dir: PathBuf) {
    let mut read_dir = match fs::read_dir(&public_dir).await {
        Ok(rd) => rd,
        Err(e) => {
            eprintln!("Failed to read directory {:?}: {}", public_dir, e);
            return;
        }
    };

    while let Ok(Some(entry)) = read_dir.next_entry().await {
        let path = entry.path();
        if path.is_file() {
            match fs::remove_file(&path).await {
                Ok(_) => {}
                Err(e) => eprintln!("Failed to delete file {:?}: {}", path, e),
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let config = get_env_paths().expect("Failed to load env config");

    tokio::spawn({
        let public_path = config.public_path.clone();

        async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(6 * 60 * 60));
            loop {
                interval.tick().await;
                clean_directories(public_path.clone()).await;
            }
        }
    });

    let app = Router::new()
        .route("/sign", post(sign_handler))
        .route(
            "/ota/{bundle_id}/{bundle_version}/{ipa_file_name}",
            get(ota_handler),
        )
        .route(
            "/install/{bundle_id}/{bundle_version}/{ipa_file_name}",
            get(install_handler),
        )
        .nest_service("/public", ServeDir::new(config.public_path.clone()))
        .layer(CorsLayer::permissive())
        .layer(axum::middleware::from_fn(inject_base_url))
        .layer(Extension(config.clone()))
        .layer(DefaultBodyLimit::disable());

    let listener = tokio::net::TcpListener::bind(":::".to_owned() + &config.port)
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}
