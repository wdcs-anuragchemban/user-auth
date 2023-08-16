use actix_web::{
    dev::Payload, error::ErrorUnauthorized, http, web, Error as ActixWebError, FromRequest,
    HttpRequest,
};
use core::fmt;
use serde::{Deserialize, Serialize};
use std::env;
use std::future::{ready, Ready};
use uuid::Uuid;

use crate::token;

#[derive(Debug, Serialize)]
struct ErrorResponse {
    status: String,
    message: String,
}

impl fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", serde_json::to_string(&self).unwrap())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtMiddleware {
    pub user: String,
    pub access_token: Uuid,
}

impl FromRequest for JwtMiddleware {
    type Error = ActixWebError;
    type Future = Ready<Result<Self, Self::Error>>;
    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        // let data = req.app_data::<web::Data<AppState>>().unwrap();

        let public_key =
            env::var("ACCESS_TOKEN_PUBLIC_KEY").expect("Access token public key not fetched");

        let access_token = req
            .cookie("access_token")
            .map(|c| c.value().to_string())
            .or_else(|| {
                req.headers()
                    .get(http::header::AUTHORIZATION)
                    .map(|h| h.to_str().unwrap().split_at(7).1.to_string())
            });

        if access_token.is_none() {
            let json_error = ErrorResponse {
                status: "FAILED".to_string(),
                message: "You are not logged in, please provide token".to_string(),
            };
            return ready(Err(ErrorUnauthorized(json_error)));
        }

        let access_token_details = match token::verify_jwt(public_key, &access_token.unwrap()) {
            Ok(token_details) => token_details,
            Err(e) => {
                let json_error = ErrorResponse {
                    status: "FAILED".to_string(),
                    message: format!("{:?}", e),
                };
                return ready(Err(ErrorUnauthorized(json_error)));
            }
        };

        let user_id = access_token_details.user_id;
        let access_token_uuid =
            Uuid::parse_str(&access_token_details.token_uuid.to_string()).unwrap();

        ready(Ok(JwtMiddleware {
            user: user_id,
            access_token: access_token_uuid,
        }))
    }
}
