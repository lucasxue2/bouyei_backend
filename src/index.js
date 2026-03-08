export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    const encoder = new TextEncoder();

    const toBase64 = (bytes) => {
      let binary = "";
      for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
      return btoa(binary);
    };

    const fromBase64 = (b64) => {
      const binary = atob(b64);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      return bytes;
    };

    const pbkdf2Hash = async (password, saltBytes) => {
      const keyMaterial = await crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        "PBKDF2",
        false,
        ["deriveBits"]
      );

      const bits = await crypto.subtle.deriveBits(
        {
          name: "PBKDF2",
          salt: saltBytes,
          iterations: 100_000,
          hash: "SHA-256",
        },
        keyMaterial,
        256
      );

      return new Uint8Array(bits);
    };

    const origin = request.headers.get("Origin");
    const allowOrigins = new Set(["https://bouyei.net", "https://www.bouyei.net"]);
    const corsHeaders = allowOrigins.has(origin)
      ? {
          "access-control-allow-origin": origin,
          "access-control-allow-methods": "GET,POST,OPTIONS",
          "access-control-allow-headers": "content-type,authorization",
          "access-control-max-age": "86400",
          vary: "Origin",
        }
      : {};

    const json = (data, status = 200, extraHeaders = {}) =>
      new Response(JSON.stringify(data), {
        status,
        headers: {
          "content-type": "application/json; charset=utf-8",
          ...corsHeaders,
          ...extraHeaders,
        },
      });

    const db = env.BOUYEI_USER;

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          ...corsHeaders,
        },
      });
    }

    if (request.method === "GET" && url.pathname === "/") {
      return new Response("working", {
        status: 200,
        headers: {
          "content-type": "text/plain; charset=utf-8",
          "cache-control": "no-store",
          ...corsHeaders,
        },
      });
    }

    if (request.method === "POST" && url.pathname === "/user/register") {
      if (!db) {
        return json({ ok: false, message: "D1 binding not configured" }, 500);
      }

      let body;
      try {
        body = await request.json();
      } catch {
        return json({ ok: false, message: "Invalid JSON" }, 400);
      }

      const email = typeof body?.email === "string" ? body.email.trim() : "";
      const password = typeof body?.password === "string" ? body.password : "";

      if (!email || !password) {
        return json({ ok: false, message: "Email and password are required" }, 400);
      }

      const normalizedEmail = email.toLowerCase();

      const existing = await db
        .prepare("SELECT id FROM users WHERE email = ?1")
        .bind(normalizedEmail)
        .first();

      if (existing?.id) {
        return json({ ok: false, message: "Email already registered" }, 409);
      }

      const saltBytes = crypto.getRandomValues(new Uint8Array(16));
      const hashBytes = await pbkdf2Hash(password, saltBytes);

      const userId = crypto.randomUUID();
      const createdAt = Date.now();

      await db
        .prepare(
          "INSERT INTO users (id, email, password_hash, password_salt, created_at) VALUES (?1, ?2, ?3, ?4, ?5)"
        )
        .bind(userId, normalizedEmail, toBase64(hashBytes), toBase64(saltBytes), createdAt)
        .run();

      return json({ ok: true, message: "registered", user: { id: userId, email: normalizedEmail } }, 200);
    }

    if (request.method === "POST" && url.pathname === "/user/login") {
      if (!db) {
        return json({ ok: false, message: "D1 binding not configured" }, 500);
      }

      let body;
      try {
        body = await request.json();
      } catch {
        return json({ ok: false, message: "Invalid JSON" }, 400);
      }

      const email = typeof body?.email === "string" ? body.email.trim() : "";
      const password = typeof body?.password === "string" ? body.password : "";

      if (!email || !password) {
        return json({ ok: false, message: "Email and password are required" }, 400);
      }

      const normalizedEmail = email.toLowerCase();

      const user = await db
        .prepare("SELECT id, email, password_hash, password_salt FROM users WHERE email = ?1")
        .bind(normalizedEmail)
        .first();

      if (!user?.id) {
        return json({ ok: false, message: "Invalid email or password" }, 401);
      }

      const saltBytes = fromBase64(user.password_salt);
      const expectedHashBytes = fromBase64(user.password_hash);
      const actualHashBytes = await pbkdf2Hash(password, saltBytes);

      if (expectedHashBytes.length !== actualHashBytes.length) {
        return json({ ok: false, message: "Invalid email or password" }, 401);
      }

      let mismatch = 0;
      for (let i = 0; i < expectedHashBytes.length; i++) mismatch |= expectedHashBytes[i] ^ actualHashBytes[i];
      if (mismatch !== 0) {
        return json({ ok: false, message: "Invalid email or password" }, 401);
      }

      const token = crypto.randomUUID();
      const createdAt = Date.now();
      const expiresAt = createdAt + 30 * 24 * 60 * 60 * 1000;

      await db
        .prepare("INSERT INTO sessions (token, user_id, expires_at, created_at) VALUES (?1, ?2, ?3, ?4)")
        .bind(token, user.id, expiresAt, createdAt)
        .run();

      return json({ ok: true, message: "logged_in", token }, 200);
    }

    return new Response("Not Found", {
      status: 404,
      headers: {
        "content-type": "text/plain; charset=utf-8",
        ...corsHeaders,
      },
    });
  },
};
