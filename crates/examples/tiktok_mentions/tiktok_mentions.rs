//! TikTok Mentions Proof-of-Concept
//!
//! Proves TikTok mention notifications using TLSNotary MPC-TLS protocol.
//! Enables Dyaka to monitor @DyakaBot mentions and prove tip comments.
//!
//! ## Setup
//!
//! 1. Log into TikTok as @DyakaBot (or test account)
//! 2. Go to Inbox -> Activity -> Mentions
//! 3. Open DevTools (F12) -> Network tab
//! 4. Find request to `api/notice/multi`
//! 5. Save the URL path+query and cookies to files
//!
//! ## Run
//!
//! ```bash
//! TIKTOK_PATH_FILE=path.txt TIKTOK_COOKIES_FILE=cookies.txt \
//!   cargo run --release --example tiktok_mentions
//! ```
//!
//! ## Notification Groups
//!
//! The `group` parameter in the API request determines notification type:
//! - group=6: Mentions (comments that @mention you)
//! - Other values: likes, comments, followers, etc.

use std::time::Instant;

use anyhow::Result;
use tlsn_examples::tiktok;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let (path, cookies, referer) = tiktok::load_config("https://www.tiktok.com/messages")?;

    println!("TikTok Mentions - TLSNotary Proof\n");

    let start = Instant::now();
    let transcript = tiktok::run_proof(&path, &cookies, &referer).await?;

    println!("\nVerification successful in {:?}", start.elapsed());
    println!(
        "Request: {} bytes | Response: {} bytes\n",
        transcript.sent_unsafe().len(),
        transcript.received_unsafe().len()
    );

    if let Some(data) = tiktok::extract_json(&transcript) {
        if let Some(code) = data.get("status_code").and_then(|c| c.as_i64()) {
            if code != 0 {
                let msg = data.get("status_msg").and_then(|m| m.as_str()).unwrap_or("unknown");
                println!("API Error: {} (code: {})", msg, code);
                return Ok(());
            }
        }

        if let Some(notice_lists) = data.get("notice_lists").and_then(|n| n.as_array()) {
            for group in notice_lists {
                let group_type = group.get("group").and_then(|g| g.as_i64()).unwrap_or(0);
                let group_name = match group_type {
                    6 => "Mentions",
                    17 => "Comments",
                    500 => "Activity",
                    _ => "Other",
                };

                if let Some(notices) = group.get("notice_list").and_then(|n| n.as_array()) {
                    println!("{} ({} notifications):\n", group_name, notices.len());

                    for (i, notice) in notices.iter().take(10).enumerate() {
                        let user = notice.get("user")
                            .and_then(|u| u.get("nickname"))
                            .and_then(|n| n.as_str())
                            .unwrap_or("?");
                        let handle = notice.get("user")
                            .and_then(|u| u.get("unique_id"))
                            .and_then(|n| n.as_str())
                            .unwrap_or("?");
                        let content = notice.get("content")
                            .and_then(|c| c.as_str())
                            .or_else(|| notice.get("text").and_then(|t| t.as_str()))
                            .unwrap_or("");

                        println!("{}. {} (@{}):", i + 1, user, handle);
                        if !content.is_empty() {
                            println!("   \"{}\"", content);
                        }

                        if content.to_lowercase().contains("tip") {
                            println!("   >> POTENTIAL TIP DETECTED");
                        }
                        println!();
                    }

                    if notices.len() > 10 {
                        println!("... and {} more", notices.len() - 10);
                    }
                }
            }
        } else {
            println!("No mention notifications found.");
        }
    } else {
        println!("Could not parse response JSON");
    }

    Ok(())
}
