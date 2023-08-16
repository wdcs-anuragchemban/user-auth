use actix_web::web::{self, Data, Json};
use actix_web::{get, post, HttpResponse};
use diesel::result::Error;

use bcrypt::{verify, DEFAULT_COST};
use diesel::prelude::*;
use diesel::{ExpressionMethods, Insertable, Queryable, RunQueryDsl};
use serde::{Deserialize, Serialize};
use std::env;
use uuid::Uuid;

use super::schema::users;
use crate::jwt_auth::JwtMiddleware;
use crate::response::{CustomError, ResponseLogin, ResponseRegister, UserData, UserDetail};
use crate::{token, DBConnection, DBPool};
use std::str::FromStr;

#[derive(Debug, Deserialize, Serialize)]
pub struct User {
    pub firstname: String,
    pub lastname: Option<String>,
    pub dateofbirth: Option<String>,
    pub email: String,
    pub password: String,
}

impl User {
    pub fn to_db_user(&self) -> UserDB {
        let hashed_password = bcrypt::hash(self.password.clone(), DEFAULT_COST).unwrap();
        UserDB {
            firstname: self.firstname.clone(),
            lastname: self.lastname.clone(),
            dateofbirth: self.dateofbirth.clone(),
            email: self.email.clone(),
            password: hashed_password,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Queryable)]
pub struct LoginUser {
    pub email: String,
    pub password: String,
}

#[diesel(table_name = users)]
#[derive(Queryable, Insertable, Debug)]
pub struct UserDB {
    pub firstname: String,
    pub lastname: Option<String>,
    pub dateofbirth: Option<String>,
    pub email: String,
    pub password: String,
}

impl UserDB {
    pub fn to_user(&self) -> User {
        User {
            firstname: self.firstname.clone(),
            lastname: self.lastname.clone(),
            dateofbirth: self.dateofbirth.clone(),
            email: self.email.clone(),
            password: self.password.clone(),
        }
    }

    pub fn to_user_details(&self) -> UserDetail {
        UserDetail {
            firstname: self.firstname.clone(),
            lastname: self.lastname.clone(),
            dateofbirth: self.dateofbirth.clone(),
            email: self.email.clone(),
        }
    }
}

pub fn create_user(userdb: UserDB, conn: &mut DBConnection) -> Result<ResponseRegister, Error> {
    use crate::schema::users::dsl::*;

    let user = userdb.to_user_details();
    let _ = diesel::insert_into(users).values(&userdb).execute(conn);

    Ok(ResponseRegister {
        result: Some(UserData { userdata: user }),
        status: "SUCCESS".to_string(),
        message: "User successfully registered".to_string(),
    })
}

pub fn authenticate_user(user: &LoginUser, user_with_password: LoginUser) -> bool {
    verify(&user.password, &user_with_password.password).unwrap()
}

pub fn login_user(user: LoginUser, conn: &mut DBConnection) -> Result<ResponseLogin, CustomError> {
    use crate::schema::users::dsl::*;

    let user_with_password = match users
        .filter(&email.eq(&user.email))
        .select((email, password))
        .first::<LoginUser>(conn)
    {
        Ok(res) => Ok(res),
        Err(_) => Err(Error::NotFound),
    };

    println!("{:?}", user_with_password);

    let auth = authenticate_user(&user, user_with_password.unwrap());

    if !auth {
        return Err(CustomError::InvalidPassword);
    }

    let ttl = env::var("ACCESS_TOKEN_MAXAGE").expect("FAILED to fetch value");
    let ttl = ttl.parse::<i64>().unwrap();
    let private_key = env::var("ACCESS_TOKEN_PRIVATE_KEY").expect("FAILED to fetch value");

    let access_token = match token::generate_jwt_token(user.email, ttl, private_key) {
        Ok(access_token) => access_token,
        Err(_) => return Err(CustomError::FailedToGenerateAccessToken),
    };

    Ok(ResponseLogin {
        status: "SUCCESS".to_string(),
        message: access_token,
    })
}

pub fn get_user_data(user_email: String, conn: &mut DBConnection) -> Result<UserDetail, CustomError> {
    use crate::schema::users::dsl::*;

    let user_details = match users
        .filter(&email.eq(user_email))
        .select((firstname, lastname, dateofbirth, email))
        .first::<UserDetail>(conn)
    {
        Ok(res) => Ok(res),
        Err(_) => Err(CustomError::NoUserFound),
    };

    user_details
}

#[post("/user/register")]
async fn register(data: Json<User>, pool: Data<DBPool>) -> HttpResponse {
    let mut conn = pool.get().expect("Cannot create connection");

    if data.password.len() < 8 || data.password.len() > 15 {
        // return Err(CustomError::InvalidPassword);
        return HttpResponse::ExpectationFailed().json("Invalid Password");
    }

    let user = web::block(move || create_user(data.to_db_user(), &mut conn)).await;
    let res = user.unwrap().unwrap();

    HttpResponse::Ok().json(res)
}

#[post("/user/login")]
async fn login(data: Json<LoginUser>, pool: Data<DBPool>) -> HttpResponse {
    let mut conn = pool.get().expect("Cannot create connection");

    let temp_data = serde_json::to_string(&data).unwrap();
    let login_data = serde_json::from_str(&temp_data).unwrap();

    let user = web::block(move || login_user(login_data, &mut conn)).await;

    match user {
        Ok(res) => HttpResponse::Ok().json(res.unwrap()),
        Err(err) => HttpResponse::BadRequest()
            .json(serde_json::json!({"status": "FAILED", "message": format!("{:?}", err)})),
    }
}

#[get("/dashboard")]
async fn dashboard(token: JwtMiddleware, pool: Data<DBPool>) -> HttpResponse {
    let mut conn = pool.get().expect("Cannot create connection");

    println!("TOKEN {:?}", token);

    let user = get_user_data(token.user, &mut conn);

    HttpResponse::Ok().json(user.unwrap())
}
