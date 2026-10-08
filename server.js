"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const path = require("node:path");
const express = require("express");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

const PORT = Number(process.env.PORT || 10000);
const DATABASE_URL = process.env.DATABASE_URL;
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL?.trim().toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SESSION_COOKIE = "__Host-cobros_session";
const SESSION_LIFETIME_MS = 1000 * 60 * 60 * 24 * 7;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_ATTEMPT_LIMIT = 10;
const MAX_STATE_BYTES = 2 * 1024 * 1024;
const USER_ROLES = new Set(["admin", "supervisor", "cashier", "inventory"]);

if (!DATABASE_URL || !FRONTEND_ORIGIN || !ADMIN_EMAIL || !ADMIN_PASSWORD) {
  console.error("Configura DATABASE_URL, FRONTEND_ORIGIN, ADMIN_EMAIL y ADMIN_PASSWORD.");
  process.exit(1);
}

if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(ADMIN_EMAIL) || ADMIN_EMAIL.length > 320) {
  console.error("ADMIN_EMAIL debe ser una dirección de correo válida.");
  process.exit(1);
}

if (!/^https:\/\//i.test(FRONTEND_ORIGIN) && process.env.NODE_ENV === "production") {
  console.error("FRONTEND_ORIGIN debe ser una dirección HTTPS en producción.");
  process.exit(1);
}

let frontendOrigin;
try {
  frontendOrigin = new URL(FRONTEND_ORIGIN);
} catch {
  console.error("FRONTEND_ORIGIN debe ser una URL HTTPS válida.");
  process.exit(1);
}

if (frontendOrigin.origin !== FRONTEND_ORIGIN) {
  console.error("FRONTEND_ORIGIN debe incluir solo el origen HTTPS, sin rutas ni barra final.");
  process.exit(1);
}

if (ADMIN_PASSWORD.length < 12 || Buffer.byteLength(ADMIN_PASSWORD, "utf8") > 72) {
  console.error("ADMIN_PASSWORD debe tener al menos 12 caracteres y no más de 72 bytes UTF-8.");
  process.exit(1);
}

const databaseUrl = new URL(DATABASE_URL);
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: databaseUrl.hostname.endsWith(".neon.tech") ? { rejectUnauthorized: true } : undefined,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});
const app = express();
const loginAttempts = new Map();
let dummyPasswordHash;

app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
}));
app.use((request, response, next) => {
  response.setHeader("Access-Control-Allow-Origin", FRONTEND_ORIGIN);
  response.setHeader("Access-Control-Allow-Credentials", "true");
  response.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS");
  response.setHeader("Access-Control-Allow-Headers", "Content-Type");
  response.setHeader("Vary", "Origin");
  if (request.method === "OPTIONS") {
    response.sendStatus(204);
    return;
  }
  next();
});
app.use(express.json({ limit: "3mb", strict: true }));

function apiError(response, status, message) {
  response.status(status).json({ error: message });
}

function normalizeEmail(value) {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

function safeUser(row) {
  return {
    id: row.id,
    email: row.email,
    displayName: row.display_name,
    role: row.role,
    photo: row.photo || "",
  };
}

function parseCookies(header = "") {
  return Object.fromEntries(header.split(";").map((entry) => {
    const separator = entry.indexOf("=");
    if (separator < 0) return ["", ""];
    return [entry.slice(0, separator).trim(), decodeURIComponent(entry.slice(separator + 1).trim())];
  }).filter(([key]) => key));
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function setSessionCookie(response, token) {
  response.setHeader(
    "Set-Cookie",
    `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_LIFETIME_MS / 1000}`,
  );
}

function clearSessionCookie(response) {
  response.setHeader(
    "Set-Cookie",
    `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
  );
}

app.use((request, response, next) => {
  if (request.path.startsWith("/api/") && request.method !== "GET" && request.method !== "HEAD") {
    if (request.get("origin") !== FRONTEND_ORIGIN) {
      apiError(response, 403, "Origen de solicitud no permitido.");
      return;
    }
  }
  next();
});

async function requireUser(request, response, next) {
  try {
    const token = parseCookies(request.headers.cookie)[SESSION_COOKIE];
    if (!token) {
      apiError(response, 401, "Inicia sesión para continuar.");
      return;
    }
    const result = await pool.query(
      `SELECT u.id, u.email, u.display_name, u.role, u.photo
       FROM app_sessions s
       JOIN app_users u ON u.id = s.user_id
       WHERE s.token_hash = $1 AND s.expires_at > now()`,
      [hashToken(token)],
    );
    if (!result.rowCount) {
      clearSessionCookie(response);
      apiError(response, 401, "La sesión expiró. Inicia sesión nuevamente.");
      return;
    }
    request.user = safeUser(result.rows[0]);
    next();
  } catch (error) {
    next(error);
  }
}

function requireAdmin(request, response, next) {
  if (request.user.role !== "admin") {
    apiError(response, 403, "Se requiere una cuenta administradora.");
    return;
  }
  next();
}

function checkLoginRateLimit(request, response) {
  const key = request.ip;
  const now = Date.now();
  if (loginAttempts.size > 10000) {
    for (const [address, attempt] of loginAttempts) {
      if (attempt.resetAt <= now) loginAttempts.delete(address);
    }
  }
  const current = loginAttempts.get(key);
  if (!current || current.resetAt <= now) {
    loginAttempts.set(key, { count: 0, resetAt: now + LOGIN_WINDOW_MS });
  }
  const attempt = loginAttempts.get(key);
  if (attempt.count >= LOGIN_ATTEMPT_LIMIT) {
    response.setHeader("Retry-After", String(Math.ceil((attempt.resetAt - now) / 1000)));
    apiError(response, 429, "Demasiados intentos. Espera antes de volver a iniciar sesión.");
    return false;
  }
  attempt.count += 1;
  return true;
}

async function createSession(response, userId) {
  const token = crypto.randomBytes(32).toString("base64url");
  await pool.query(
    "INSERT INTO app_sessions (token_hash, user_id, expires_at) VALUES ($1, $2, now() + interval '7 days')",
    [hashToken(token), userId],
  );
  setSessionCookie(response, token);
}

function validateBusinessState(state) {
  if (!state || typeof state !== "object" || Array.isArray(state)) return false;
  const collectionsValid = ["services", "clients", "payments", "monthlyCharges"]
    .every((key) => Array.isArray(state[key]) && state[key].length <= 50000);
  const profile = state.companyProfile;
  const profileValid = profile && typeof profile === "object" && !Array.isArray(profile)
    && typeof profile.name === "string" && profile.name.length <= 160
    && typeof profile.address === "string" && profile.address.length <= 1000
    && typeof profile.phone === "string" && profile.phone.length <= 100
    && typeof profile.logo === "string" && profile.logo.length <= 1500000
    && (!profile.logo || /^data:image\/(png|jpeg|webp);base64,/.test(profile.logo));
  return collectionsValid && profileValid;
}

function sameValue(left, right) {
  return JSON.stringify(left ?? null) === JSON.stringify(right ?? null);
}

function stateCollection(state, key) {
  return Array.isArray(state[key]) ? state[key] : [];
}

function preservesExistingRecords(previous, next) {
  const nextById = new Map(next.map((record) => [record.id, record]));
  return previous.every((record) => sameValue(record, nextById.get(record.id)));
}

function preservesProductsExceptStock(previous, next) {
  if (previous.length !== next.length) return false;
  const nextById = new Map(next.map((product) => [product.id, product]));
  return previous.every((product) => {
    const updated = nextById.get(product.id);
    if (!updated) return false;
    const { stock: previousStock, ...previousDetails } = product;
    const { stock: updatedStock, ...updatedDetails } = updated;
    return sameValue(previousDetails, updatedDetails)
      && Number.isFinite(Number(updatedStock))
      && Number(updatedStock) >= 0
      && Number(updatedStock) <= Number(previousStock);
  });
}

function canUpdateBusinessState(role, previous, next) {
  if (role === "admin") return true;
  if (role === "supervisor") return sameValue(previous.companyProfile, next.companyProfile);
  if (role === "cashier") {
    return sameValue(previous.services, next.services)
      && sameValue(stateCollection(previous, "productPurchases"), stateCollection(next, "productPurchases"))
      && sameValue(previous.companyProfile, next.companyProfile)
      && preservesProductsExceptStock(stateCollection(previous, "products"), stateCollection(next, "products"))
      && preservesExistingRecords(previous.payments, next.payments)
      && preservesExistingRecords(stateCollection(previous, "productSales"), stateCollection(next, "productSales"));
  }
  if (role === "inventory") {
    return sameValue(previous.services, next.services)
      && sameValue(previous.clients, next.clients)
      && sameValue(previous.payments, next.payments)
      && sameValue(previous.monthlyCharges, next.monthlyCharges)
      && sameValue(previous.companyProfile, next.companyProfile);
  }
  return false;
}

function loginAttemptKey(request) {
  return request.ip;
}

app.get("/healthz", async (_request, response, next) => {
  try {
    await pool.query("SELECT 1");
    response.json({ status: "ok" });
  } catch (error) {
    next(error);
  }
});

app.post("/api/auth/login", async (request, response, next) => {
  if (!checkLoginRateLimit(request, response)) return;
  try {
    const email = normalizeEmail(request.body?.email);
    const password = request.body?.password;
    if (!email || typeof password !== "string" || password.length > 256) {
      apiError(response, 400, "Escribe tu correo y contraseña.");
      return;
    }
    const result = await pool.query(
      "SELECT id, email, password_hash, display_name, role, photo FROM app_users WHERE email = $1",
      [email],
    );
    const account = result.rows[0];
    const valid = account
      ? await bcrypt.compare(password, account.password_hash)
      : await bcrypt.compare(password, dummyPasswordHash);
    if (!valid || !account) {
      apiError(response, 401, "Credenciales inválidas.");
      return;
    }
    loginAttempts.delete(loginAttemptKey(request));
    await createSession(response, account.id);
    response.json({ user: safeUser(account) });
  } catch (error) {
    next(error);
  }
});

app.get("/api/auth/session", requireUser, (request, response) => {
  response.json({ user: request.user });
});

app.post("/api/auth/logout", requireUser, async (request, response, next) => {
  try {
    const token = parseCookies(request.headers.cookie)[SESSION_COOKIE];
    await pool.query("DELETE FROM app_sessions WHERE token_hash = $1", [hashToken(token)]);
    clearSessionCookie(response);
    response.json({ ok: true });
  } catch (error) {
    next(error);
  }
});

app.post("/api/auth/change-password", requireUser, async (request, response, next) => {
  try {
    const { currentPassword, newPassword } = request.body || {};
    if (typeof currentPassword !== "string" || typeof newPassword !== "string"
      || newPassword.length < 12 || Buffer.byteLength(newPassword, "utf8") > 72) {
      apiError(response, 400, "La nueva contraseña debe tener al menos 12 caracteres y no más de 72 bytes UTF-8.");
      return;
    }
    const result = await pool.query("SELECT password_hash FROM app_users WHERE id = $1", [request.user.id]);
    if (!await bcrypt.compare(currentPassword, result.rows[0].password_hash)) {
      apiError(response, 401, "La contraseña actual no es correcta.");
      return;
    }
    const passwordHash = await bcrypt.hash(newPassword, 12);
    await pool.query("UPDATE app_users SET password_hash = $1 WHERE id = $2", [passwordHash, request.user.id]);
    const currentToken = parseCookies(request.headers.cookie)[SESSION_COOKIE];
    await pool.query("DELETE FROM app_sessions WHERE user_id = $1 AND token_hash <> $2", [request.user.id, hashToken(currentToken)]);
    response.json({ ok: true });
  } catch (error) {
    next(error);
  }
});

app.patch("/api/auth/profile", requireUser, async (request, response, next) => {
  try {
    const displayName = typeof request.body?.displayName === "string" ? request.body.displayName.trim() : "";
    const photo = typeof request.body?.photo === "string" ? request.body.photo : "";
    if (!displayName || displayName.length > 120 || photo.length > 1500000
      || (photo && !/^data:image\/(png|jpeg|webp);base64,/.test(photo))) {
      apiError(response, 400, "El nombre o la foto no son válidos.");
      return;
    }
    const result = await pool.query(
      "UPDATE app_users SET display_name = $1, photo = $2 WHERE id = $3 RETURNING id, email, display_name, role, photo",
      [displayName, photo, request.user.id],
    );
    response.json({ user: safeUser(result.rows[0]) });
  } catch (error) {
    next(error);
  }
});

app.get("/api/users", requireUser, requireAdmin, async (_request, response, next) => {
  try {
    const result = await pool.query(
      "SELECT id, email, display_name, role, photo FROM app_users ORDER BY created_at, email",
    );
    response.json({ users: result.rows.map(safeUser) });
  } catch (error) {
    next(error);
  }
});

app.post("/api/users", requireUser, requireAdmin, async (request, response, next) => {
  try {
    const email = normalizeEmail(request.body?.email);
    const displayName = typeof request.body?.displayName === "string" ? request.body.displayName.trim() : "";
    const password = request.body?.password;
    const role = typeof request.body?.role === "string" ? request.body.role : "cashier";
    if (!USER_ROLES.has(role)) {
      apiError(response, 400, "Selecciona un rol válido.");
      return;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !displayName || displayName.length > 120
      || typeof password !== "string" || password.length < 12 || password.length > 72
      || Buffer.byteLength(password, "utf8") > 72) {
      apiError(response, 400, "Revisa el correo, nombre y contraseña (12 a 72 caracteres UTF-8).");
      return;
    }
    const passwordHash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      `INSERT INTO app_users (id, email, password_hash, display_name, role)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, email, display_name, role, photo`,
      [crypto.randomUUID(), email, passwordHash, displayName, role],
    );
    response.status(201).json({ user: safeUser(result.rows[0]) });
  } catch (error) {
    if (error.code === "23505") {
      apiError(response, 409, "Ese correo ya tiene una cuenta.");
      return;
    }
    next(error);
  }
});

app.patch("/api/users/:id", requireUser, requireAdmin, async (request, response, next) => {
  const { id } = request.params;
  const role = request.body?.role;
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id)
    || typeof role !== "string" || !USER_ROLES.has(role)) {
    apiError(response, 400, "El usuario o el rol seleccionado no son válidos.");
    return;
  }
  if (id === request.user.id) {
    apiError(response, 400, "No puedes cambiar el rol de la cuenta activa.");
    return;
  }

  let client;
  let transactionStarted = false;
  try {
    client = await pool.connect();
    await client.query("BEGIN");
    transactionStarted = true;
    const admins = await client.query("SELECT id FROM app_users WHERE role = 'admin' ORDER BY id FOR UPDATE");
    const result = await client.query(
      "SELECT id, email, display_name, role, photo FROM app_users WHERE id = $1 FOR UPDATE",
      [id],
    );
    if (!result.rowCount) {
      await client.query("ROLLBACK");
      transactionStarted = false;
      apiError(response, 404, "No se encontró ese usuario.");
      return;
    }
    if (result.rows[0].role === "admin" && role !== "admin") {
      if (admins.rowCount <= 1) {
        await client.query("ROLLBACK");
        transactionStarted = false;
        apiError(response, 400, "No puedes quitar el último rol de administrador.");
        return;
      }
    }
    const updated = await client.query(
      "UPDATE app_users SET role = $1 WHERE id = $2 RETURNING id, email, display_name, role, photo",
      [role, id],
    );
    await client.query("COMMIT");
    transactionStarted = false;
    response.json({ user: safeUser(updated.rows[0]) });
  } catch (error) {
    if (transactionStarted && client) await client.query("ROLLBACK");
    next(error);
  } finally {
    if (client) client.release();
  }
});

app.delete("/api/users/:id", requireUser, requireAdmin, async (request, response, next) => {
  try {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(request.params.id)) {
      apiError(response, 400, "El identificador de usuario no es válido.");
      return;
    }
    if (request.params.id === request.user.id) {
      apiError(response, 400, "No puedes eliminar la sesión administradora activa.");
      return;
    }
    const result = await pool.query(
      "DELETE FROM app_users WHERE id = $1 AND role <> 'admin' RETURNING id",
      [request.params.id],
    );
    if (!result.rowCount) {
      apiError(response, 404, "No se encontró ese usuario.");
      return;
    }
    response.json({ ok: true });
  } catch (error) {
    next(error);
  }
});

app.get("/api/state", requireUser, async (_request, response, next) => {
  try {
    const result = await pool.query("SELECT version, data FROM business_state WHERE id = 1");
    response.json({ version: Number(result.rows[0].version), state: result.rows[0].data });
  } catch (error) {
    next(error);
  }
});

app.post("/api/state/import", requireUser, requireAdmin, async (request, response, next) => {
  try {
    const state = request.body?.state;
    if (!validateBusinessState(state) || Buffer.byteLength(JSON.stringify(state), "utf8") > MAX_STATE_BYTES) {
      apiError(response, 400, "Los datos para importar no tienen un formato válido o exceden el límite permitido.");
      return;
    }
    const result = await pool.query(
      `UPDATE business_state
       SET data = $1::jsonb, version = version + 1, imported_at = now(), updated_at = now()
       WHERE id = 1 AND version = 0 AND imported_at IS NULL
       RETURNING version, data`,
      [JSON.stringify(state)],
    );
    if (!result.rowCount) {
      apiError(response, 409, "La importación inicial ya se realizó o la base contiene cambios.");
      return;
    }
    response.json({ version: Number(result.rows[0].version), state: result.rows[0].data });
  } catch (error) {
    next(error);
  }
});

app.put("/api/state", requireUser, async (request, response, next) => {
  try {
    const { version, state } = request.body || {};
    if (!Number.isSafeInteger(version) || version < 0 || !validateBusinessState(state)
      || Buffer.byteLength(JSON.stringify(state), "utf8") > MAX_STATE_BYTES) {
      apiError(response, 400, "Los datos enviados no tienen un formato válido o exceden el límite permitido.");
      return;
    }
    const current = await pool.query("SELECT version, data FROM business_state WHERE id = 1");
    if (Number(current.rows[0].version) !== version) {
      apiError(response, 409, "Los datos cambiaron en otro dispositivo. Recarga la aplicación antes de guardar.");
      return;
    }
    if (!canUpdateBusinessState(request.user.role, current.rows[0].data, state)) {
      apiError(response, 403, "Tu rol no tiene permiso para realizar estos cambios.");
      return;
    }
    const result = await pool.query(
      `UPDATE business_state
       SET data = $1::jsonb, version = version + 1, updated_at = now()
       WHERE id = 1 AND version = $2
       RETURNING version, data`,
      [JSON.stringify(state), version],
    );
    if (!result.rowCount) {
      apiError(response, 409, "Los datos cambiaron en otro dispositivo. Recarga la aplicación antes de guardar.");
      return;
    }
    response.json({ version: Number(result.rows[0].version), state: result.rows[0].data });
  } catch (error) {
    next(error);
  }
});

app.use((error, _request, response, _next) => {
  console.error("Error de API:", error);
  if (response.headersSent) return;
  if (error.type === "entity.too.large") {
    apiError(response, 413, "La solicitud es demasiado grande.");
    return;
  }
  if (error instanceof SyntaxError && error.status === 400) {
    apiError(response, 400, "El JSON recibido no es válido.");
    return;
  }
  apiError(response, 500, "Ocurrió un error del servidor. Intenta nuevamente.");
});

async function startServer() {
  const schema = await fs.readFile(path.join(__dirname, "schema.sql"), "utf8");
  await pool.query(schema);
  dummyPasswordHash = await bcrypt.hash(crypto.randomBytes(32).toString("hex"), 12);
  const bootstrapEmail = ADMIN_EMAIL;
  const bootstrapPasswordHash = await bcrypt.hash(ADMIN_PASSWORD, 12);
  const bootstrapClient = await pool.connect();
  let bootstrapTransactionStarted = false;
  try {
    await bootstrapClient.query("BEGIN");
    bootstrapTransactionStarted = true;
    await bootstrapClient.query("SELECT id FROM business_state WHERE id = 1 FOR UPDATE");
    const existingUsers = await bootstrapClient.query("SELECT count(*)::int AS count FROM app_users");
    if (existingUsers.rows[0].count === 0) {
      await bootstrapClient.query(
        `INSERT INTO app_users (id, email, password_hash, display_name, role)
         VALUES ($1, $2, $3, $4, 'admin')`,
        [crypto.randomUUID(), bootstrapEmail, bootstrapPasswordHash, "Administración"],
      );
      console.info("Se creó la cuenta administradora inicial indicada en ADMIN_EMAIL.");
    }
    await bootstrapClient.query("COMMIT");
    bootstrapTransactionStarted = false;
  } catch (error) {
    if (bootstrapTransactionStarted) await bootstrapClient.query("ROLLBACK");
    throw error;
  } finally {
    bootstrapClient.release();
  }
  await pool.query("DELETE FROM app_sessions WHERE expires_at <= now()");
  const sessionCleanupTimer = setInterval(() => {
    pool.query("DELETE FROM app_sessions WHERE expires_at <= now()")
      .catch((error) => console.error("No se pudieron limpiar las sesiones expiradas.", error));
  }, 60 * 60 * 1000);
  sessionCleanupTimer.unref();
  const server = app.listen(PORT, "0.0.0.0", () => {
    console.info(`API iniciada en el puerto ${PORT}.`);
  });
  const shutdown = async () => {
    server.close(async () => {
      await pool.end();
      process.exit(0);
    });
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

startServer().catch(async (error) => {
  console.error("No se pudo iniciar el servidor. Revisa la base de datos y las variables configuradas.", error);
  await pool.end();
  process.exit(1);
});
