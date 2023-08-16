// @generated automatically by Diesel CLI.

diesel::table! {
    users (email) {
        #[max_length = 20]
        firstname -> Varchar,
        #[max_length = 20]
        lastname -> Nullable<Varchar>,
        #[max_length = 10]
        dateofbirth -> Nullable<Varchar>,
        #[max_length = 50]
        email -> Varchar,
        password -> Text,
    }
}
