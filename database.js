const sqlite3 = require('sqlite3').verbose();

// Connect to SQLite database
const db = new sqlite3.Database('./webauthn.db', (err) => {
    if (err) {
        console.error(err.message);
    } else {
        console.log('Connected to the SQLite database.');
    }
});

// Create Users table
const createUsersTable = () => {
    const query = `
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE
        );
    `;
    return db.run(query);
};

// Create Authenticators table
const createAuthenticatorsTable = () => {
    const query = `
        CREATE TABLE IF NOT EXISTS authenticators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            credential_id TEXT NOT NULL,
            public_key TEXT NOT NULL,
            sign_count INTEGER NOT NULL,
            aaguid TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    `;
    return db.run(query);
};

// Initialize database tables
createUsersTable();
createAuthenticatorsTable();

// Function to add a new user
const addUser = (username, callback) => {
    const query = `INSERT INTO users (username) VALUES (?)`;
    db.run(query, [username], function(err) {
        callback(err, this.lastID); // Return the last inserted row id
    });
};

// Function to add an authenticator for a user
const addAuthenticator = (userId, credentialId, publicKey, signCount, aaguid, callback) => {
    const query = `INSERT INTO authenticators (user_id, credential_id, public_key, sign_count, aaguid) VALUES (?, ?, ?, ?, ?)`;
    db.run(query, [userId, credentialId, publicKey, signCount, aaguid], callback);
};

// Function to retrieve a user by username
const getUserByUsername = (username, callback) => {
    const query = `SELECT * FROM users WHERE username = ?`;
    db.get(query, [username], callback);
};

// Function to retrieve authenticators for a user
const getAuthenticatorsByUserId = (userId, callback) => {
    const query = `SELECT * FROM authenticators WHERE user_id = ?`;
    db.all(query, [userId], callback);
};

module.exports = {
    addUser,
    getUserByUsername,
    addAuthenticator,
    getAuthenticatorsByUserId
};
