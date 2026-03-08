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
          "access-control-allow-credentials": "true",
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

    const parseCookies = (cookieHeader) => {
      const out = {};
      if (!cookieHeader) return out;
      const parts = cookieHeader.split(";");
      for (const part of parts) {
        const idx = part.indexOf("=");
        if (idx === -1) continue;
        const k = part.slice(0, idx).trim();
        const v = part.slice(idx + 1).trim();
        out[k] = v;
      }
      return out;
    };

    const buildSidCookie = (sid, maxAgeSeconds) => {
      const attrs = [
        `sid=${sid}`,
        "Path=/",
        "HttpOnly",
        "Secure",
        "SameSite=Lax",
        "Domain=.bouyei.net",
      ];
      if (typeof maxAgeSeconds === "number") attrs.push(`Max-Age=${maxAgeSeconds}`);
      return attrs.join("; ");
    };

    const getOrCreateSession = async () => {
      if (!db) return { sid: null, setCookie: null, session: null };

      const cookies = parseCookies(request.headers.get("Cookie"));
      let sid = typeof cookies.sid === "string" && cookies.sid ? cookies.sid : null;

      if (sid) {
        const session = await db
          .prepare("SELECT token, user_id, expires_at FROM sessions WHERE token = ?1")
          .bind(sid)
          .first();

        if (session?.token && session.expires_at > Date.now()) {
          return { sid, setCookie: null, session };
        }
      }

      sid = crypto.randomUUID();
      const createdAt = Date.now();
      const expiresAt = createdAt + 30 * 24 * 60 * 60 * 1000;
      await db
        .prepare("INSERT INTO sessions (token, user_id, expires_at, created_at) VALUES (?1, NULL, ?2, ?3)")
        .bind(sid, expiresAt, createdAt)
        .run();

      return {
        sid,
        setCookie: buildSidCookie(sid, 30 * 24 * 60 * 60),
        session: { token: sid, user_id: null, expires_at: expiresAt },
      };
    };

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          ...corsHeaders,
        },
      });
    }

    if (!db) {
      return json({ ok: false, message: "D1 binding not configured" }, 500);
    }

    const { sid, setCookie, session } = await getOrCreateSession();

    if (request.method === "GET" && url.pathname === "/") {
      return new Response("working", {
        status: 200,
        headers: {
          "content-type": "text/plain; charset=utf-8",
          "cache-control": "no-store",
          ...corsHeaders,
          ...(setCookie ? { "set-cookie": setCookie } : {}),
        },
      });
    }

    if (request.method === "POST" && url.pathname === "/user/register") {
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

      return json(
        { ok: true, message: "registered", user: { id: userId, email: normalizedEmail } },
        200,
        setCookie ? { "set-cookie": setCookie } : {}
      );
    }

    if (request.method === "POST" && url.pathname === "/user/login") {
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

      if (sid) {
        await db
          .prepare("UPDATE sessions SET user_id = ?1, expires_at = ?2 WHERE token = ?3")
          .bind(user.id, expiresAt, sid)
          .run();

        return json(
          { ok: true, message: "logged_in" },
          200,
          setCookie ? { "set-cookie": setCookie } : {}
        );
      }

      await db
        .prepare("INSERT INTO sessions (token, user_id, expires_at, created_at) VALUES (?1, ?2, ?3, ?4)")
        .bind(token, user.id, expiresAt, createdAt)
        .run();

      return json(
        { ok: true, message: "logged_in" },
        200,
        { "set-cookie": buildSidCookie(token, 30 * 24 * 60 * 60) }
      );
    }

    if (request.method === "POST" && url.pathname === "/user/logout") {
      if (sid) {
        await db.prepare("UPDATE sessions SET user_id = NULL WHERE token = ?1").bind(sid).run();
      }

      return json({ ok: true, message: "logged_out" }, 200, setCookie ? { "set-cookie": setCookie } : {});
    }

    if (request.method === "GET" && url.pathname === "/user/me") {
      if (!sid) return json({ ok: false, message: "Not logged in" }, 401);

      const sess = await db
        .prepare("SELECT token, user_id, expires_at FROM sessions WHERE token = ?1")
        .bind(sid)
        .first();

      if (!sess?.token || sess.expires_at <= Date.now() || !sess.user_id) {
        return json({ ok: false, message: "Not logged in" }, 401, setCookie ? { "set-cookie": setCookie } : {});
      }

      const user = await db.prepare("SELECT id, email, created_at FROM users WHERE id = ?1").bind(sess.user_id).first();
      if (!user?.id) {
        return json({ ok: false, message: "Not logged in" }, 401, setCookie ? { "set-cookie": setCookie } : {});
      }

      return json({ ok: true, user }, 200, setCookie ? { "set-cookie": setCookie } : {});
    }

    if (request.method === "GET" && url.pathname === "/cart") {
      if (!sid) return json({ ok: false, message: "No session" }, 400);

      const items = await db
        .prepare("SELECT product_id, qty FROM cart_items WHERE session_token = ?1 ORDER BY product_id")
        .bind(sid)
        .all();

      return json({ ok: true, items: items?.results || [] }, 200, setCookie ? { "set-cookie": setCookie } : {});
    }

    if (request.method === "POST" && url.pathname === "/cart/items") {
      if (!sid) return json({ ok: false, message: "No session" }, 400);

      let body;
      try {
        body = await request.json();
      } catch {
        return json({ ok: false, message: "Invalid JSON" }, 400, setCookie ? { "set-cookie": setCookie } : {});
      }

      const productId = typeof body?.product_id === "string" ? body.product_id.trim() : "";
      const qty = Number.isFinite(body?.qty) ? body.qty : parseInt(body?.qty, 10);

      if (!productId || !Number.isFinite(qty)) {
        return json({ ok: false, message: "product_id and qty are required" }, 400, setCookie ? { "set-cookie": setCookie } : {});
      }

      const now = Date.now();

      if (qty <= 0) {
        await db.prepare("DELETE FROM cart_items WHERE session_token = ?1 AND product_id = ?2").bind(sid, productId).run();
        return json({ ok: true, message: "removed" }, 200, setCookie ? { "set-cookie": setCookie } : {});
      }

      await db
        .prepare(
          "INSERT INTO cart_items (session_token, product_id, qty, updated_at) VALUES (?1, ?2, ?3, ?4) " +
            "ON CONFLICT(session_token, product_id) DO UPDATE SET qty = excluded.qty, updated_at = excluded.updated_at"
        )
        .bind(sid, productId, qty, now)
        .run();

      return json({ ok: true, message: "updated" }, 200, setCookie ? { "set-cookie": setCookie } : {});
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
