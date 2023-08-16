-- Your SQL goes here

CREATE EXTENSION "uuid-ossp";

CREATE TABLE Users (
    firstname VARCHAR(20) NOT NULL,
    lastname VARCHAR(20),
    dateofbirth VARCHAR(10),
    email VARCHAR(50) PRIMARY KEY NOT NULL,
    password TEXT NOT NULL 
);