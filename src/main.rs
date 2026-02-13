use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Extension, Multipart, Path, Request},
    http::StatusCode,
    middleware::Next,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::json;
use std::collections::HashSet;
use std::env;
use std::error::Error;
use std::path::PathBuf;
use tokio::{fs, io::AsyncWriteExt};
use std::ffi::{CString, CStr};
use libc::{c_char, c_void, free};
use std::fs::File;
use zip::ZipArchive;
use tower_http::{
    services::ServeDir,
    cors::CorsLayer,
};
use tempfile::TempDir;
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
    work_path: &PathBuf
) -> Result<SignResult, Box<dyn Error>> {
    unsafe extern "C" {
        fn zsign_sign_folder_to_ipa(app_folder: *const c_char, output_ipa: *const c_char, prov_path: *const c_char, key_path: *const c_char, out_bundle_id: *mut *mut c_char, out_bundle_ver: *mut *mut c_char) -> i32;
    }

    if !input_ipa.is_file() {
        return Err(format!("The input IPA file does not exist: {}", input_ipa.display()).into());
    }

    let td = TempDir::with_prefix_in(input_ipa, work_path)?;
    let input_ipa_file = File::open(&input_ipa)?;
    let mut archive = ZipArchive::new(input_ipa_file)?;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;

        if let Some(enclosed) = file.enclosed_name() {
            let outpath = td.path().join(enclosed);

            if file.name().ends_with('/') {
                std::fs::create_dir_all(&outpath)?;
            } else {
                if let Some(parent) = outpath.parent() {
                    std::fs::create_dir_all(parent)?;
                }

                let mut outfile = File::create(&outpath)?;
                std::io::copy(&mut file, &mut outfile)?;
            }
        }
    }

    let c_input = CString::new(td.path().to_path_buf().to_string_lossy().to_string())?;
    let c_output = CString::new(output_ipa.to_string_lossy().to_string())?;
    let c_prov = CString::new(ota_prov.to_string_lossy().to_string())?;
    let c_key = CString::new(key.to_string_lossy().to_string())?;

    let mut out_bid: *mut c_char = std::ptr::null_mut();
    let mut out_bver: *mut c_char = std::ptr::null_mut();

    let rc = unsafe {
        zsign_sign_folder_to_ipa(c_input.as_ptr(), c_output.as_ptr(), c_prov.as_ptr(), c_key.as_ptr(), &mut out_bid, &mut out_bver)
    };

    if rc != 0 {
        return Err(format!("zsign returned error code {}", rc).into());
    }

    let bundle_id = if !out_bid.is_null() {
        unsafe { CStr::from_ptr(out_bid).to_string_lossy().into_owned() }
    } else {
        return Err("Missing bundle id or version from zsign".into());
    };

    let bundle_ver = if !out_bver.is_null() {
        unsafe { CStr::from_ptr(out_bver).to_string_lossy().into_owned() }
    } else {
        return Err("Missing bundle id or version from zsign".into());
    };

    if !out_bid.is_null() {
        unsafe { free(out_bid as *mut c_void); }
    }

    if !out_bver.is_null() {
        unsafe { free(out_bver as *mut c_void); }
    }

    Ok(SignResult { bundle_id, bundle_ver })
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

async fn init_upload_handler(
    Extension(config): Extension<Config>,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let mut udid = None;

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
        }
    }

    let udid = match udid {
        Some(u) => u,
        None => {
            return Err((
                StatusCode::BAD_REQUEST,
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

    let upload_id = Uuid::new_v4().to_string();
    let chunk_path = config.work_path.join("chunks").join(&upload_id);

    fs::create_dir_all(&chunk_path).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "message": format!("Unable to create chunks dir: {}", e) })),
        )
    })?;

    Ok((
        StatusCode::OK,
        Json(json!({ "upload_id": upload_id })),
    ))
}

async fn upload_chunk_handler(
    Extension(config): Extension<Config>,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let mut upload_id = None;
    let mut chunk_index = None;
    let mut file_bytes = None;

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

        if name == "upload_id" {
            let text = field.text().await.unwrap_or_default();
            upload_id = Some(text);
        } else if name == "chunk_index" {
            let text = field.text().await.unwrap_or_default();
            if let Ok(idx) = text.parse::<usize>() {
                chunk_index = Some(idx);
            }
        } else if name == "file" {
            let bytes = field.bytes().await.map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "message": format!("Error reading file field: {}", e) })),
                )
            })?;
            file_bytes = Some(bytes);
        }
    }

    if upload_id.is_none() || chunk_index.is_none() || file_bytes.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "message": "Missing upload_id, chunk_index, or file." })),
        ));
    }

    let upload_id = upload_id.unwrap();
    let chunk_index = chunk_index.unwrap();
    let bytes = file_bytes.unwrap();

    let chunk_dir = config.work_path.join("chunks").join(&upload_id);
    if !chunk_dir.exists() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "message": "Upload session not found." })),
        ));
    }

    let chunk_path = chunk_dir.join(format!("{}.part", chunk_index));

    let mut file = fs::File::create(&chunk_path).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "message": format!("Unable to save chunk: {}", e) })),
        )
    })?;

    file.write_all(&bytes).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "message": format!("Unable to write chunk: {}", e) })),
        )
    })?;

    Ok((StatusCode::OK, Json(json!({ "status": "ok" }))))
}

async fn finish_upload_handler(
    Extension(config): Extension<Config>,
    Extension(base_url): Extension<String>,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let mut upload_id = None;

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

        if name == "upload_id" {
            let text = field.text().await.unwrap_or_default();
            upload_id = Some(text);
        }
    }

    let upload_id = match upload_id {
        Some(u) => u,
        None => return Err((StatusCode::BAD_REQUEST, Json(json!({ "message": "Missing upload_id." })))),
    };

    let chunk_dir = config.work_path.join("chunks").join(&upload_id);
    if !chunk_dir.exists() {
        return Err((StatusCode::NOT_FOUND, Json(json!({ "message": "Upload session not found." }))));
    }

    let mut chunks = Vec::new();
    let mut entries = fs::read_dir(&chunk_dir).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "message": format!("Error reading chunks dir: {}", e) })),
        )
    })?;

    while let Ok(Some(entry)) = entries.next_entry().await {
        if let Some(stem) = entry.path().file_stem().and_then(|s| s.to_str()) {
            if let Ok(idx) = stem.parse::<usize>() {
                chunks.push((idx, entry.path()));
            }
        }
    }
    chunks.sort_by_key(|k| k.0);

    let uuid = Uuid::new_v4();
    let timestamp = chrono::Utc::now().timestamp_millis();
    let ipa_name = format!(
        "{}_{}_{}.ipa",
        timestamp, uuid, upload_id
    );
    let work_ipa_path = config.work_path.join(&ipa_name);
    let output_ipa_path = config.public_path.join(&ipa_name);

    let mut target_file = fs::File::create(&work_ipa_path).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "message": format!("Unable to create work IPA: {}", e) })),
        )
    })?;

    for (_, chunk_path) in chunks {
        let mut chunk_file = fs::File::open(&chunk_path).await.map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "message": format!("Unable to open chunk: {}", e) })),
            )
        })?;
        tokio::io::copy(&mut chunk_file, &mut target_file).await.map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "message": format!("Unable to append chunk: {}", e) })),
            )
        })?;
    }

    let _ = fs::remove_dir_all(&chunk_dir).await;

    let sign_result = sign_ipa(
        &work_ipa_path,
        &output_ipa_path,
        &config.otaprov_path,
        &config.key_path,
        &config.work_path
    )
    .await
    .map_err(|e| {
        let _ = tokio::fs::remove_file(&work_ipa_path);
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

async fn clean_directories(public_dir: PathBuf, work_dir: PathBuf) {
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

    let chunks_dir = work_dir.join("chunks");
    if let Ok(mut read_dir) = fs::read_dir(&chunks_dir).await {
        while let Ok(Some(entry)) = read_dir.next_entry().await {
            let path = entry.path();
            if path.is_dir() {
                match fs::remove_dir_all(&path).await {
                    Ok(_) => {}
                    Err(e) => eprintln!("Failed to delete chunks dir {:?}: {}", path, e),
                }
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let config = get_env_paths().expect("Failed to load env config");
    let _ = fs::create_dir_all(config.work_path.join("chunks")).await;

    tokio::spawn({
        let public_path = config.public_path.clone();
        let work_path = config.work_path.clone();

        async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(6 * 60 * 60));
            loop {
                interval.tick().await;
                clean_directories(public_path.clone(), work_path.clone()).await;
            }
        }
    });

    let app = Router::new()
        .route("/upload/init", post(init_upload_handler))
        .route("/upload/chunk", post(upload_chunk_handler))
        .route("/upload/finish", post(finish_upload_handler))
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
