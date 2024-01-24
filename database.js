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
            userId TEXT NOT NULL,
            email TEXT NOT NULL,
            publicKey TEXT NOT NULL
        )
    `;

    return db.run(query);
};

// Initialize database
createUsersTable();

// Function to add a new user
const addUser = (userId, email, publicKey, callback) => {
    const query = `INSERT INTO users (userId, email, publicKey) VALUES (?, ?, ?)`;
    db.run(query, [userId, email, publicKey], callback);
};

// Function to retrieve a user by email
const getUserByEmail = (email, callback) => {
    const query = `SELECT * FROM users WHERE email = ?`;
    db.get(query, [email], callback);
};


const getUserById = (id, callback) => {
    const query = `SELECT * FROM users WHERE userId = ?`;
    db.get(query, [email], callback);
};

module.exports = {
    addUser,
    getUserByEmail
};
