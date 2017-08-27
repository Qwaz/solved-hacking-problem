CREATE TABLE users (
    username varchar(256),
    password varchar(256),
    PRIMARY KEY(username)
);

CREATE TABLE files (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    realname varchar(256),
    path varchar(256)
);

CREATE TABLE notes (
    username varchar(256),
    data varchar(5000)
);

