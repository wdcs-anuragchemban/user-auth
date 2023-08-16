use actix_web::web::Data;
use actix_web::{App, HttpServer};
// use config::Config;
use diesel::r2d2::{self, ConnectionManager, Pool, PooledConnection};
use diesel::PgConnection;
use dotenv::dotenv;
use std::env;
use std::io::Result;

// mod config;
mod jwt_auth;
mod model;
mod response;
mod schema;
mod token;
mod user;

pub type DBPool = Pool<ConnectionManager<PgConnection>>;
pub type DBConnection = PooledConnection<ConnectionManager<PgConnection>>;

#[actix_web::main]
async fn main() -> Result<()> {
    dotenv().ok();

    // let config = Config::init();

    let database_url = env::var("DATABASE_URL").expect("could not read DATABASE_URL");
    let db_connection = ConnectionManager::<PgConnection>::new(database_url);

    let pool = match r2d2::Pool::builder().build(db_connection) {
        Ok(pool) => {
            println!("Successfully connected to a database");
            pool
        }
        Err(err) => {
            println!("Failed to connect to db, {}", err);
            std::process::exit(1)
        }
    };

    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(pool.clone()))
            .service(user::register)
            .service(user::login)
            .service(user::dashboard)
    })
    .bind(("127.0.0.1", 8000))?
    .run()
    .await
}
