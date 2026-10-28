require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const { v2: cloudinary } = require("cloudinary");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");
const POSTS_FILE = path.join(DATA_DIR, "posts.json");
const FRONTEND_URL = process.env.FRONTEND_URL;
const MAX_IMAGE_BYTES = 5 * 1024 * 1024;

if (!JWT_SECRET) {
  console.error("Falta la variable obligatoria JWT_SECRET.");
  process.exit(1);
}
if (process.env.CLOUDINARY_CLOUD_NAME && process.env.CLOUDINARY_API_KEY && process.env.CLOUDINARY_API_SECRET) {
  cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
  });
}
const uploadsReady = !!(process.env.CLOUDINARY_CLOUD_NAME && process.env.CLOUDINARY_API_KEY && process.env.CLOUDINARY_API_SECRET);
const allowedOrigins = (FRONTEND_URL || "").split(",").map(s => s.trim()).filter(Boolean);

function ensureJsonFile(file, initialValue) {
  if (!fs.existsSync(file)) fs.writeFileSync(file, JSON.stringify(initialValue, null, 2), "utf8");
}
function readJson(file) {
  try { return JSON.parse(fs.readFileSync(file, "utf8")); }
  catch { return []; }
}
function writeJson(file, value) {
  fs.writeFileSync(file, JSON.stringify(value, null, 2), "utf8");
}
function nextId(items) {
  return items.reduce((max, item) => Math.max(max, Number(item.id) || 0), 0) + 1;
}
function publicUser(user) {
  return { id: Number(user.id), name: user.name, email: user.email, avatar_url: user.avatar_url || null };
}
function makeToken(user) {
  return jwt.sign({ sub: String(user.id) }, JWT_SECRET, { expiresIn: "30d" });
}
function auth(req, res, next) {
  const raw = req.headers.authorization || "";
  const token = raw.startsWith("Bearer ") ? raw.slice(7) : "";
  if (!token) return res.status(401).json({ error: "Inicia sesión para continuar." });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const users = readJson(USERS_FILE);
    const user = users.find(u => String(u.id) === String(payload.sub));
    if (!user) return res.status(401).json({ error: "La sesión ya no es válida." });
    req.user = user;
    next();
  } catch {
    return res.status(401).json({ error: "Sesión inválida o caducada. Inicia sesión otra vez." });
  }
}
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_IMAGE_BYTES, files: 1 },
  fileFilter(req, file, cb) {
    if (!file.mimetype || !file.mimetype.startsWith("image/")) return cb(new Error("Solo se permiten imágenes."));
    cb(null, true);
  }
});
async function imageToCloudinary(file, folder) {
  if (!uploadsReady) throw new Error("La subida de imágenes aún no está configurada. Añade las credenciales de Cloudinary en Render.");
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream({ folder, resource_type: "image" }, (error, result) => {
      if (error) return reject(error);
      resolve(result.secure_url);
    });
    stream.end(file.buffer);
  });
}

app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));
app.use(cors({
  origin(origin, callback) {
    if (!origin || !allowedOrigins.length || allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error("Origen no permitido por CORS."));
  }
}));
app.use(express.json({ limit: "100kb" }));
app.get("/", (req, res) => res.json({ name: "KIV API", status: "online", storage: "JSON temporal" }));
app.get("/api/health", (req, res) => res.json({ ok: true, storage: "json" }));

app.post("/api/auth/register", async (req, res, next) => {
  try {
    const name = String(req.body.name || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    if (name.length < 2 || name.length > 40) return res.status(400).json({ error: "El nombre debe tener entre 2 y 40 caracteres." });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) return res.status(400).json({ error: "Escribe un correo válido." });
    if (password.length < 8 || password.length > 72) return res.status(400).json({ error: "La contraseña debe tener entre 8 y 72 caracteres." });
    const users = readJson(USERS_FILE);
    if (users.some(u => u.email === email)) return res.status(409).json({ error: "Ese correo ya tiene una cuenta." });
    const user = { id: nextId(users), name, email, password_hash: await bcrypt.hash(password, 12), avatar_url: null, created_at: new Date().toISOString() };
    users.push(user); writeJson(USERS_FILE, users);
    res.status(201).json({ token: makeToken(user), user: publicUser(user) });
  } catch (err) { next(err); }
});
app.post("/api/auth/login", async (req, res, next) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    const user = readJson(USERS_FILE).find(u => u.email === email);
    if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: "Correo o contraseña incorrectos." });
    res.json({ token: makeToken(user), user: publicUser(user) });
  } catch (err) { next(err); }
});
app.get("/api/me", auth, (req, res) => res.json(publicUser(req.user)));
app.patch("/api/me", auth, upload.single("avatar"), async (req, res, next) => {
  try {
    const name = String(req.body.name || "").trim();
    if (name.length < 2 || name.length > 40) return res.status(400).json({ error: "El nombre debe tener entre 2 y 40 caracteres." });
    const users = readJson(USERS_FILE);
    const index = users.findIndex(u => String(u.id) === String(req.user.id));
    if (index < 0) return res.status(404).json({ error: "No se encontró el perfil." });
    let avatar_url = users[index].avatar_url || null;
    if (req.file) avatar_url = await imageToCloudinary(req.file, "kiv/avatars");
    users[index] = { ...users[index], name, avatar_url };
    writeJson(USERS_FILE, users);
    res.json(publicUser(users[index]));
  } catch (err) { next(err); }
});
app.get("/api/posts", (req, res) => {
  const users = readJson(USERS_FILE);
  const posts = readJson(POSTS_FILE).sort((a,b) => new Date(b.created_at) - new Date(a.created_at)).slice(0,100);
  res.json(posts.map(p => {
    const user = users.find(u => String(u.id) === String(p.user_id)) || {};
    return { ...p, id: Number(p.id), user_id: Number(p.user_id), name: user.name || "Usuario de KIV", avatar_url: user.avatar_url || null };
  }));
});
app.post("/api/posts", auth, upload.single("image"), async (req, res, next) => {
  try {
    const text = String(req.body.text || "").trim();
    if (text.length > 1000) return res.status(400).json({ error: "El texto no puede superar 1000 caracteres." });
    if (!text && !req.file) return res.status(400).json({ error: "Escribe algo o adjunta una imagen." });
    let image_url = null;
    if (req.file) image_url = await imageToCloudinary(req.file, "kiv/posts");
    const posts = readJson(POSTS_FILE);
    const post = { id: nextId(posts), user_id: Number(req.user.id), text, image_url, created_at: new Date().toISOString() };
    posts.push(post); writeJson(POSTS_FILE, posts);
    res.status(201).json({ ...post, name: req.user.name, avatar_url: req.user.avatar_url || null });
  } catch (err) { next(err); }
});
app.delete("/api/posts/:id", auth, (req, res) => {
  const posts = readJson(POSTS_FILE);
  const index = posts.findIndex(p => String(p.id) === String(req.params.id) && String(p.user_id) === String(req.user.id));
  if (index < 0) return res.status(404).json({ error: "No se encontró tu publicación." });
  posts.splice(index, 1); writeJson(POSTS_FILE, posts);
  res.json({ ok: true });
});
app.use((err, req, res, next) => {
  console.error(err.message || err);
  if (err instanceof multer.MulterError && err.code === "LIMIT_FILE_SIZE") return res.status(400).json({ error: "La imagen supera el límite de 5 MB." });
  if (err.message === "Solo se permiten imágenes.") return res.status(400).json({ error: err.message });
  if (err.message === "Origen no permitido por CORS.") return res.status(403).json({ error: err.message });
  res.status(500).json({ error: err.message && err.message.startsWith("La subida de imágenes") ? err.message : "Error interno del servidor." });
});

fs.mkdirSync(DATA_DIR, { recursive: true });
ensureJsonFile(USERS_FILE, []);
ensureJsonFile(POSTS_FILE, []);
app.listen(PORT, "0.0.0.0", () => console.log(`KIV API escuchando en ${PORT}; almacenamiento JSON en ${DATA_DIR}`));
