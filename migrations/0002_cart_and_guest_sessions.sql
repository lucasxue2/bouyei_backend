PRAGMA foreign_keys=OFF;

CREATE TABLE IF NOT EXISTS sessions_new (
  token TEXT PRIMARY KEY,
  user_id TEXT,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

INSERT INTO sessions_new (token, user_id, expires_at, created_at)
SELECT token, user_id, expires_at, created_at FROM sessions;

DROP TABLE sessions;
ALTER TABLE sessions_new RENAME TO sessions;

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS cart_items (
  session_token TEXT NOT NULL,
  product_id TEXT NOT NULL,
  qty INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (session_token, product_id),
  FOREIGN KEY (session_token) REFERENCES sessions(token)
);

CREATE INDEX IF NOT EXISTS idx_cart_items_session ON cart_items(session_token);

PRAGMA foreign_keys=ON;
