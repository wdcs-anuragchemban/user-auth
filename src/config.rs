use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub access_token_private_key: String,
    pub access_token_public_key: String,
    pub access_token_expire_time: String,
    pub access_token_maxage: i64,
}

fn get_env(string: &str) -> String {
    env::var(string).expect(format!("could not read {}", string).as_str())
}

impl Config {
    pub fn init() -> Config {
        let database_url = get_env("DATABASE_URL");
        let access_token_private_key = get_env("ACCESS_TOKEN_PRIVATE_KEY");
        let access_token_public_key = get_env("ACCESS_TOKEN_PUBLIC_KEY");
        let access_token_expire_time = get_env("ACCESS_TOKEN_EXPIRE_TIME");
        let access_token_maxage = get_env("ACCESS_TOKEN_MAXAGE");

        Config {
            database_url: database_url,
            access_token_private_key: access_token_private_key,
            access_token_public_key: access_token_public_key,
            access_token_expire_time: access_token_expire_time,
            access_token_maxage: access_token_maxage.parse::<i64>().unwrap(),
        }
    }
}
