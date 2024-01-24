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
            username TEXT NOT NULL,
            publicKey TEXT NOT NULL
        )
    `;

    return db.run(query);
};

// Initialize database
createUsersTable();

// Function to add a new user
const addUser = (username, publicKey, callback) => {
    const query = `INSERT INTO users (username, publicKey) VALUES (?, ?, ?)`;
    db.run(query, [username, email, publicKey], callback);
};

// Function to retrieve a user by ID
const getUserById = (id, callback) => {
    const query = `SELECT * FROM users WHERE username = ?`;
    db.get(query, [email], callback);
};

module.exports = {
    addUser,
    getUserById
};
