/**
 * Standalone Node.js example using Express to handle OAuth 2.0 login with Google, storing user data in a SQLite database
 */

const express = require("express");
const axios = require("axios");
const sqlite3 = require("sqlite3").verbose();
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const jwksClient = require("jwks-rsa");

const app = express();
const db = new sqlite3.Database(":memory:");

// Initialize database
db.serialize(() => {
  db.run(
    "CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, email TEXT)"
  );
  db.run(
    "CREATE TABLE federated_credentials (user_id INTEGER, provider TEXT, subject TEXT, PRIMARY KEY (provider, subject))"
  );
});

// Configuration
const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const REDIRECT_URI = "https://example.com/oauth2/callback";
const SCOPE = "openid profile email";

// JWKS client to fetch Google's public keys
const jwks = jwksClient({
  jwksUri: "https://www.googleapis.com/oauth2/v3/certs",
});

// Function to verify JWT
async function verifyIdToken(idToken) {
  return new Promise((resolve, reject) => {
    jwt.verify(
      idToken,
      (header, callback) => {
        jwks.getSigningKey(header.kid, (err, key) => {
          callback(null, key.getPublicKey());
        });
      },
      {
        audience: CLIENT_ID,
        issuer: "https://accounts.google.com",
      },
      (err, decoded) => {
        if (err) return reject(err);
        resolve(decoded);
      }
    );
  });
}

// Generate a random state for CSRF protection
app.get("/login", (req, res) => {
  const state = crypto.randomBytes(16).toString("hex");
  req.session.state = state; // Store state in session
  const authUrl = `https://accounts.google.com/o/oauth2/auth?client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&scope=${SCOPE}&response_type=code&state=${state}`;
  res.redirect(authUrl);
});

// OAuth callback
app.get("/oauth2/callback", async (req, res) => {
  const { code, state } = req.query;

  // Verify state to prevent CSRF
  if (state !== req.session.state) {
    return res.status(403).send("Invalid state parameter");
  }

  try {
    // Exchange code for tokens
    const tokenResponse = await axios.post(
      "https://oauth2.googleapis.com/token",
      {
        code,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        redirect_uri: REDIRECT_URI,
        grant_type: "authorization_code",
      }
    );

    const { id_token } = tokenResponse.data;

    // Verify ID token (JWT)
    const decoded = await verifyIdToken(id_token);
    const { sub: subject, name, email } = decoded;

    // Check if user exists in federated_credentials
    db.get(
      "SELECT * FROM federated_credentials WHERE provider = ? AND subject = ?",
      ["https://accounts.google.com", subject],
      (err, cred) => {
        if (err) return res.status(500).send("Database error");

        if (!cred) {
          // New user: create account
          db.run(
            "INSERT INTO users (name, email) VALUES (?, ?)",
            [name, email],
            function (err) {
              if (err) return res.status(500).send("Database error");

              const userId = this.lastID;
              db.run(
                "INSERT INTO federated_credentials (user_id, provider, subject) VALUES (?, ?, ?)",
                [userId, "https://accounts.google.com", subject],
                (err) => {
                  if (err) return res.status(500).send("Database error");
                  res.send(`Logged in as ${name} (${email})`);
                }
              );
            }
          );
        } else {
          // Existing user: fetch and log in
          db.get(
            "SELECT * FROM users WHERE id = ?",
            [cred.user_id],
            (err, user) => {
              if (err || !user) return res.status(500).send("Database error");
              res.send(`Logged in as ${user.name} (${user.email})`);
            }
          );
        }
      }
    );
  } catch (error) {
    res.status(500).send("OAuth or JWT verification error");
  }
});

app.listen(3000, () => console.log("Server running on port 3000"));
