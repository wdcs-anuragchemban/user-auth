use actix_web::cookie::time::Duration;
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct Token {
    pub token: Option<String>,
    pub token_uuid: Uuid,
    pub user_id: String,
    pub exp: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub token_uuid: String,
    pub user_id: String,
    pub exp: i64,
    pub iat: i64,
    pub nbf: i64,
}

pub fn generate_jwt_token(
    user_id: String,
    ttl: i64,
    private_key: String,
) -> Result<String, jsonwebtoken::errors::Error> {
    let bytes_private_key = general_purpose::STANDARD.decode(private_key).unwrap();
    let decoded_private_key = String::from_utf8(bytes_private_key).unwrap();

    let now = chrono::Utc::now();

    let mut token_details = Token {
        user_id: user_id,
        token_uuid: Uuid::new_v4(),
        exp: Some((now + chrono::Duration::minutes(ttl)).timestamp()),
        token: None,
    };

    let token_claims = TokenClaims {
        token_uuid: token_details.token_uuid.to_string(),
        user_id: token_details.user_id.to_string(),
        exp: token_details.exp.unwrap(),
        iat: now.timestamp(),
        nbf: now.timestamp(),
    };

    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    let token = jsonwebtoken::encode(
        &header,
        &token_claims,
        &jsonwebtoken::EncodingKey::from_rsa_pem(decoded_private_key.as_bytes())?,
    )?;

    // token_details.token = Some(token);

    Ok(token)
}

pub fn verify_jwt(public_key: String, token: &str) -> Result<Token, jsonwebtoken::errors::Error> {
    let bytes_public_key = general_purpose::STANDARD.decode(public_key).unwrap();
    let decoded_public_key = String::from_utf8(bytes_public_key).unwrap();

    let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);

    let decoded_token = jsonwebtoken::decode::<TokenClaims>(
        token,
        &jsonwebtoken::DecodingKey::from_rsa_pem(decoded_public_key.as_bytes()).unwrap(),
        &validation,
    )?;
    println!("{:?}", decoded_token.claims.user_id.as_str());

    let user_id = decoded_token.claims.user_id;
    let token_uuid = Uuid::parse_str(decoded_token.claims.token_uuid.as_str()).unwrap();

    Ok(Token {
        token: None,
        token_uuid: token_uuid,
        user_id: user_id.to_string(),
        exp: None,
    })
}
