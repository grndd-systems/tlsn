//! TikTok Comments Proof-of-Concept
//!
//! Proves TikTok comments using TLSNotary MPC-TLS protocol.
//!
//! ## Setup
//!
//! 1. Open a TikTok video, DevTools (F12) → Network tab
//! 2. Filter by "comment", scroll to load comments
//! 3. Copy the `api/comment/list` request URL path+query to a file
//! 4. Copy the Cookie header value to another file
//!
//! ## Run
//!
//! ```bash
//! TIKTOK_PATH_FILE=path.txt TIKTOK_COOKIES_FILE=cookies.txt \
//!   cargo run --release --example tiktok_comments
//! ```

use std::time::Instant;

use anyhow::Result;
use tlsn_examples::tiktok;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let (path, cookies, referer) = tiktok::load_config("https://www.tiktok.com/")?;

    let video_id = path
        .split("aweme_id=")
        .nth(1)
        .and_then(|s| s.split('&').next())
        .unwrap_or("unknown");

    println!("TikTok Comments - TLSNotary Proof");
    println!("Video ID: {}\n", video_id);

    let start = Instant::now();
    let transcript = tiktok::run_proof(&path, &cookies, &referer).await?;

    println!("\nVerification successful in {:?}", start.elapsed());
    println!(
        "Request: {} bytes | Response: {} bytes\n",
        transcript.sent_unsafe().len(),
        transcript.received_unsafe().len()
    );

    if let Some(data) = tiktok::extract_json(&transcript) {
        if let Some(comments) = data.get("comments").and_then(|c| c.as_array()) {
            println!("Verified {} comments:\n", comments.len());
            for (i, c) in comments.iter().take(10).enumerate() {
                let user = c.get("user")
                    .and_then(|u| u.get("nickname"))
                    .and_then(|n| n.as_str())
                    .unwrap_or("?");
                let handle = c.get("user")
                    .and_then(|u| u.get("unique_id"))
                    .and_then(|n| n.as_str())
                    .unwrap_or("?");
                let text = c.get("text").and_then(|t| t.as_str()).unwrap_or("");
                let likes = c.get("digg_count").and_then(|d| d.as_u64()).unwrap_or(0);

                println!("{}. {} (@{}):", i + 1, user, handle);
                println!("   \"{}\" ({} likes)\n", text, likes);
            }
            if comments.len() > 10 {
                println!("... and {} more", comments.len() - 10);
            }
        }
    } else {
        println!("Could not parse response JSON");
    }

    Ok(())
}
