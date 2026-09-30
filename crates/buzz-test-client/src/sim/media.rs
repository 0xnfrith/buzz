//! Blossom media upload (BUD-01 / PUT /media/upload, fallback PUT /upload).

use std::time::Instant;

use anyhow::{anyhow, bail, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use image::codecs::jpeg::JpegEncoder;
use image::{ExtendedColorType, ImageEncoder};
use nostr::{EventBuilder, JsonUtil, Keys, Kind, Tag, Timestamp};
use sha2::{Digest, Sha256};

use super::guard::{HttpClient, Target};

pub struct UploadResult {
    pub url: String,
    pub bytes: u64,
    pub put_ms: f64,
}

/// 1×1 red JPEG (339 bytes), same fixture as the media e2e tests.
const TINY_JPEG: &[u8] = &[
    0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01,
    0x00, 0x01, 0x00, 0x00, 0xFF, 0xDB, 0x00, 0x43, 0x00, 0x08, 0x06, 0x06, 0x07, 0x06, 0x05, 0x08,
    0x07, 0x07, 0x07, 0x09, 0x09, 0x08, 0x0A, 0x0C, 0x14, 0x0D, 0x0C, 0x0B, 0x0B, 0x0C, 0x19, 0x12,
    0x13, 0x0F, 0x14, 0x1D, 0x1A, 0x1F, 0x1E, 0x1D, 0x1A, 0x1C, 0x1C, 0x20, 0x24, 0x2E, 0x27, 0x20,
    0x22, 0x2C, 0x23, 0x1C, 0x1C, 0x28, 0x37, 0x29, 0x2C, 0x30, 0x31, 0x34, 0x34, 0x34, 0x1F, 0x27,
    0x39, 0x3D, 0x38, 0x32, 0x3C, 0x2E, 0x33, 0x34, 0x32, 0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x01,
    0x00, 0x01, 0x01, 0x01, 0x11, 0x00, 0xFF, 0xC4, 0x00, 0x1F, 0x00, 0x00, 0x01, 0x05, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0xFF, 0xC4, 0x00, 0xB5, 0x10, 0x00, 0x02, 0x01, 0x03,
    0x03, 0x02, 0x04, 0x03, 0x05, 0x05, 0x04, 0x04, 0x00, 0x00, 0x01, 0x7D, 0x01, 0x02, 0x03, 0x00,
    0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06, 0x13, 0x51, 0x61, 0x07, 0x22, 0x71, 0x14, 0x32,
    0x81, 0x91, 0xA1, 0x08, 0x23, 0x42, 0xB1, 0xC1, 0x15, 0x52, 0xD1, 0xF0, 0x24, 0x33, 0x62, 0x72,
    0x82, 0x09, 0x0A, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x34, 0x35,
    0x36, 0x37, 0x38, 0x39, 0x3A, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x53, 0x54, 0x55,
    0x56, 0x57, 0x58, 0x59, 0x5A, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x73, 0x74, 0x75,
    0x76, 0x77, 0x78, 0x79, 0x7A, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x92, 0x93, 0x94,
    0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xB2,
    0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9,
    0xCA, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6,
    0xE7, 0xE8, 0xE9, 0xEA, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFF, 0xDA,
    0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00, 0x7B, 0x94, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xD9,
];

/// Keep only the JPEG markers Buzz's media sanitizer allows: SOI, canonical
/// JFIF APP0, DQT, SOF0, DHT, SOS + scan, EOI. Drops COM and other APPn.
fn strip_jpeg_to_canonical(bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.len() < 4 || bytes[0] != 0xff || bytes[1] != 0xd8 {
        bail!("jpeg encode did not start with SOI");
    }
    let mut out = vec![0xff, 0xd8];
    let mut i = 2usize;
    let mut in_scan = false;
    while i < bytes.len() {
        if bytes[i] != 0xff {
            if in_scan {
                out.push(bytes[i]);
                i += 1;
                continue;
            }
            bail!("jpeg marker expected at {i}");
        }
        let start = i;
        while i < bytes.len() && bytes[i] == 0xff {
            i += 1;
        }
        if i >= bytes.len() {
            bail!("truncated jpeg marker");
        }
        let marker = bytes[i];
        i += 1;
        if in_scan && marker == 0x00 {
            out.extend_from_slice(&bytes[start..i]);
            continue;
        }
        if (0xd0..=0xd7).contains(&marker) || marker == 0x01 {
            out.extend_from_slice(&bytes[start..i]);
            continue;
        }
        if marker == 0xd9 {
            out.extend_from_slice(&[0xff, 0xd9]);
            return Ok(out);
        }
        if i + 2 > bytes.len() {
            bail!("truncated jpeg length");
        }
        let len = u16::from_be_bytes([bytes[i], bytes[i + 1]]) as usize;
        let end = i
            .checked_add(len)
            .filter(|&end| end <= bytes.len())
            .ok_or_else(|| anyhow!("truncated jpeg segment"))?;
        let keep = match marker {
            0xe0 => {
                let payload = &bytes[i + 2..end];
                payload.len() >= 14
                    && payload.starts_with(b"JFIF\0")
                    && payload.len() == 14 + 3 * payload[12] as usize * payload[13] as usize
            }
            0xdb | 0xc0 | 0xc4 | 0xda => true,
            _ => false,
        };
        if keep {
            out.extend_from_slice(&bytes[start..end]);
        }
        i = end;
        in_scan = marker == 0xda;
    }
    bail!("jpeg encode missing EOI")
}

/// Encode `payload` as a metadata-free grayscale JPEG the relay will accept.
///
/// Random pixels keep the object mostly incompressible. COM/APP1+ segments
/// are stripped so Buzz's canonical-JPEG sanitizer does not 422.
pub fn canonical_jpeg(payload: &[u8]) -> Result<Vec<u8>> {
    let target = payload.len().max(TINY_JPEG.len());
    let mut side = 16u32;
    let mut last = TINY_JPEG.to_vec();
    for _ in 0..8 {
        let n = (side as usize).saturating_mul(side as usize);
        let mut pixels = vec![0u8; n];
        if payload.is_empty() {
            for (i, p) in pixels.iter_mut().enumerate() {
                *p = (i % 251) as u8;
            }
        } else {
            for (i, p) in pixels.iter_mut().enumerate() {
                *p = payload[i % payload.len()];
            }
        }
        let mut encoded = Vec::new();
        let mut encoder = JpegEncoder::new_with_quality(&mut encoded, 92);
        encoder
            .encode(&pixels, side, side, ExtendedColorType::L8)
            .map_err(|e| anyhow!("jpeg encode: {e}"))?;
        last = strip_jpeg_to_canonical(&encoded)?;
        if last.len() >= target || side >= 2048 {
            break;
        }
        side = (side.saturating_mul(2)).min(2048);
    }
    Ok(last)
}

fn blossom_auth(keys: &Keys, sha256: &str) -> Result<nostr::Event> {
    let exp = (Timestamp::now().as_secs() + 300).to_string();
    Ok(EventBuilder::new(Kind::from(24242), "Upload")
        .tags([
            Tag::parse(["t", "upload"])?,
            Tag::parse(["x", sha256])?,
            Tag::parse(["expiration", &exp])?,
        ])
        .sign_with_keys(keys)?)
}

fn auth_header(event: &nostr::Event) -> String {
    format!(
        "Nostr {}",
        URL_SAFE_NO_PAD.encode(event.as_json().as_bytes())
    )
}

/// One Blossom `PUT`. An agent that is admitted through its owner (NIP-OA)
/// rather than as a direct relay member must carry its credential in
/// `x-auth-tag`, or the relay refuses the upload.
fn upload_request(
    http: &reqwest::Client,
    url: &str,
    authorization: &str,
    sha: &str,
    body: Vec<u8>,
    auth_tag: Option<&str>,
) -> reqwest::RequestBuilder {
    let req = http
        .put(url)
        .header("Authorization", authorization)
        .header("Content-Type", "image/jpeg")
        .header("X-SHA-256", sha)
        .body(body);
    match auth_tag {
        Some(tag) => req.header("x-auth-tag", tag),
        None => req,
    }
}

/// `http` comes from [`super::guard::http_client`] and `http_url` from the
/// target guard: both uploads go to that checked address, with no proxy and
/// no redirect.
pub async fn upload(
    http: &HttpClient,
    http_url: &Target,
    keys: &Keys,
    body: Vec<u8>,
    auth_tag: Option<&str>,
) -> Result<UploadResult> {
    // Fleet image rejects application/octet-stream, invalid JPEGs, and any
    // COM/APP metadata channel. Encode the incompressible payload as a
    // canonical grayscale JFIF the sanitizer will accept and decode.
    let body = canonical_jpeg(&body)?;
    let sha = hex::encode(Sha256::digest(&body));
    let auth = blossom_auth(keys, &sha)?;
    let header = auth_header(&auth);
    let bytes = body.len() as u64;
    let paths = [http_url.join("/media/upload")?, http_url.join("/upload")?];
    let mut last_err = anyhow!("media upload failed");
    for (i, url) in paths.iter().enumerate() {
        let start = Instant::now();
        let resp = upload_request(
            http.inner(),
            url.as_str(),
            &header,
            &sha,
            body.clone(),
            auth_tag,
        )
        .send()
        .await;
        match resp {
            Ok(resp) => {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                if status.is_success() {
                    let put_ms = start.elapsed().as_secs_f64() * 1e3;
                    let url = serde_json::from_str::<serde_json::Value>(&text)
                        .ok()
                        .and_then(|v| v.get("url").and_then(|u| u.as_str()).map(|s| s.to_string()))
                        .unwrap_or_else(|| format!("{http_url}/media/{sha}"));
                    return Ok(UploadResult { url, bytes, put_ms });
                }
                last_err = anyhow!("media upload HTTP {status}: {text}");
                if i == 0 && (status.as_u16() == 404 || status.as_u16() == 405) {
                    continue;
                }
                break;
            }
            Err(e) => last_err = anyhow!("media upload: {e}"),
        }
    }
    Err(last_err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_upload_carries_its_nip_oa_tag() {
        let http = reqwest::Client::new();
        let tag = "[\"auth\",\"owner\",\"\",\"sig\"]";
        let agent = upload_request(
            &http,
            "http://127.0.0.1:9/media/upload",
            "Nostr x",
            "ab",
            vec![1],
            Some(tag),
        )
        .build()
        .expect("request");
        assert_eq!(
            agent
                .headers()
                .get("x-auth-tag")
                .and_then(|v| v.to_str().ok()),
            Some(tag)
        );
        let human = upload_request(
            &http,
            "http://127.0.0.1:9/media/upload",
            "Nostr x",
            "ab",
            vec![1],
            None,
        )
        .build()
        .expect("request");
        assert!(human.headers().get("x-auth-tag").is_none());
    }

    #[test]
    fn canonical_jpeg_is_jfif_without_com() {
        let payload = vec![0x41u8; 8 * 1024];
        let jpeg = canonical_jpeg(&payload).expect("encode");
        assert!(jpeg.len() > TINY_JPEG.len(), "got {} bytes", jpeg.len());
        assert_eq!(&jpeg[..2], &[0xff, 0xd8]);
        assert_eq!(&jpeg[jpeg.len() - 2..], &[0xff, 0xd9]);
        assert!(
            !jpeg.windows(2).any(|w| w == [0xff, 0xfe]),
            "COM marker is a metadata channel"
        );
        assert!(
            jpeg.windows(5).any(|w| w == b"JFIF\0"),
            "missing canonical JFIF APP0"
        );
    }
}
