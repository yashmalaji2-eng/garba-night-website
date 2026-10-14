import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import Razorpay from "razorpay";
import crypto from "node:crypto";
import QRCode from "qrcode";
import Database from "better-sqlite3";
import dotenv from "dotenv";

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;
const db = new Database(process.env.DB_PATH || "garba.sqlite");
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS bookings (
  id TEXT PRIMARY KEY,
  customer_name TEXT NOT NULL,
  email TEXT NOT NULL,
  phone TEXT NOT NULL,
  pass_type TEXT NOT NULL,
  event_date TEXT NOT NULL DEFAULT '2026-10-17',
  quantity INTEGER NOT NULL,
  amount_paise INTEGER NOT NULL,
  currency TEXT NOT NULL DEFAULT 'INR',
  status TEXT NOT NULL DEFAULT 'created',
  razorpay_order_id TEXT UNIQUE,
  razorpay_payment_id TEXT UNIQUE,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS tickets (
  id TEXT PRIMARY KEY,
  booking_id TEXT NOT NULL REFERENCES bookings(id),
  used_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);
// Safe migration for existing local SQLite databases created before event-date selection.
const bookingColumns = db.prepare('PRAGMA table_info(bookings)').all().map(column => column.name);
if (!bookingColumns.includes('event_date')) db.exec("ALTER TABLE bookings ADD COLUMN event_date TEXT NOT NULL DEFAULT '2026-10-17'");

const prices = {
  "stag": { name: "Stag Entry", paise: 29900, quantityLimit: 10 },
  "couple": { name: "Couple Pass", paise: 49900, quantityLimit: 10 },
  "group5": { name: "Group of 5", paise: 99900, quantityLimit: 5 }
};
const razorpay = process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET
  ? new Razorpay({ key_id: process.env.RAZORPAY_KEY_ID, key_secret: process.env.RAZORPAY_KEY_SECRET })
  : null;
const allowedOrigin = "https://yashmalaji2-eng.github.io";

app.use((req, res, next) => {
  const origin = req.headers.origin;

  if (origin === allowedOrigin) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  }

  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.static("public"));
app.use("/api", rateLimit({ windowMs: 60_000, limit: 60, standardHeaders: true, legacyHeaders: false }));

// Webhooks need the exact raw body for signature verification, so mount before express.json().
app.post("/api/razorpay-webhook", express.raw({ type: "application/json" }), (req, res) => {
  if (!process.env.RAZORPAY_WEBHOOK_SECRET) return res.status(503).send("Webhook not configured");
  const signature = req.get("x-razorpay-signature") || "";
  const expected = crypto.createHmac("sha256", process.env.RAZORPAY_WEBHOOK_SECRET).update(req.body).digest("hex");
  if (!safeEqual(signature, expected)) return res.status(400).send("Invalid signature");
  const event = JSON.parse(req.body.toString("utf8"));
  if (event.event === "payment.captured") {
    const payment = event.payload?.payment?.entity;
    if (payment?.order_id) finalizePaidOrder(payment.order_id, payment.id);
  }
  if (event.event === "payment.failed") {
    const payment = event.payload?.payment?.entity;
    if (payment?.order_id) db.prepare("UPDATE bookings SET status='payment_failed' WHERE razorpay_order_id=? AND status='created'").run(payment.order_id);
  }
  res.json({ received: true });
});

app.use(express.json({ limit: "30kb" }));
app.get("/api/config", (_req, res) => res.json({
  eventName: "Garba Night 3.0",
  venue: "Lavish Garden Road, opposite Srinivas Gardens, Kusugal, Bengeri, Hubballi, Karnataka 580023, India",
  paymentConfigured: Boolean(razorpay && process.env.RAZORPAY_KEY_ID),
  passes: Object.entries(prices).map(([id, p]) => ({ id, name: p.name, amount: p.paise / 100 }))
}));

app.post("/api/bookings", async (req, res) => {
  if (!razorpay) return res.status(503).json({ error: "Online payment is not configured yet. The organizer must set Razorpay credentials on the server." });
  const { name, email, phone, eventDate, passType, quantity } = req.body || {};
  const pass = prices[passType];
  const qty = Number(quantity);
  if (typeof name !== "string" || name.trim().length < 2 || name.trim().length > 100 ||
      typeof email !== "string" || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      typeof phone !== "string" || phone.trim().length < 7 || phone.length > 25 ||
      !["2026-10-17", "2026-10-18"].includes(eventDate) ||
      !pass || !Number.isInteger(qty) || qty < 1 || qty > pass.quantityLimit) {
    return res.status(400).json({ error: "Please provide valid booking details and quantity." });
  }
  const bookingId = crypto.randomUUID();
  const amountPaise = pass.paise * qty;
  try {
    const order = await razorpay.orders.create({
      amount: amountPaise, currency: "INR", receipt: bookingId,
      notes: { bookingId, passType, eventDate, quantity: String(qty) }
    });
    db.prepare(`INSERT INTO bookings (id,customer_name,email,phone,pass_type,event_date,quantity,amount_paise,status,razorpay_order_id)
      VALUES (?,?,?,?,?,?,?,?,'created',?)`).run(
        bookingId, name.trim(), email.trim().toLowerCase(), phone.trim(), pass.name, eventDate, qty, amountPaise, order.id
      );
    res.status(201).json({
      bookingId, orderId: order.id, amount: amountPaise, currency: "INR",
      keyId: process.env.RAZORPAY_KEY_ID, customer: { name: name.trim(), email: email.trim(), phone: phone.trim() }
    });
  } catch (err) {
    console.error("Order creation failed", err?.message);
    res.status(502).json({ error: "Could not start payment. Please try again." });
  }
});

function safeEqual(a, b) {
  const aa = Buffer.from(String(a)); const bb = Buffer.from(String(b));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
function finalizePaidOrder(orderId, paymentId) {
  const booking = db.prepare("SELECT * FROM bookings WHERE razorpay_order_id=?").get(orderId);
  if (!booking || booking.status === "paid") return;
  const txn = db.transaction(() => {
    db.prepare("UPDATE bookings SET status='paid', razorpay_payment_id=? WHERE id=? AND status!='paid'").run(paymentId, booking.id);
    const insert = db.prepare("INSERT OR IGNORE INTO tickets (id,booking_id) VALUES (?,?)");
    for (let i = 0; i < booking.quantity; i++) insert.run(crypto.randomBytes(18).toString("hex"), booking.id);
  });
  txn();
}

// Checkout signature validation. Webhook remains the authoritative async confirmation path.
app.post("/api/payment/verify", (req, res) => {
  const { bookingId, razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body || {};
  if (![bookingId, razorpay_order_id, razorpay_payment_id, razorpay_signature].every(v => typeof v === "string" && v.length < 300)) {
    return res.status(400).json({ error: "Invalid payment verification data." });
  }
  const booking = db.prepare("SELECT * FROM bookings WHERE id=? AND razorpay_order_id=?").get(bookingId, razorpay_order_id);
  if (!booking) return res.status(404).json({ error: "Booking not found." });
  const expected = crypto.createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
    .update(`${razorpay_order_id}|${razorpay_payment_id}`).digest("hex");
  if (!safeEqual(razorpay_signature, expected)) return res.status(400).json({ error: "Payment signature could not be verified." });
  finalizePaidOrder(razorpay_order_id, razorpay_payment_id);
  res.json({ status: "verification_received", message: "Payment signature verified. Ticket access is available after server confirmation." });
});

// Only reveals tickets for a paid booking when the unguessable booking id is provided.
// For a public production site, add email OTP or another customer verification step before exposing ticket details.
app.get("/api/bookings/:id/tickets", async (req, res) => {
  const booking = db.prepare("SELECT id,status,pass_type,event_date,quantity FROM bookings WHERE id=?").get(req.params.id);
  if (!booking) return res.status(404).json({ error: "Booking not found." });
  if (booking.status !== "paid") return res.status(409).json({ error: "Tickets are available only after payment is confirmed." });
  const tickets = db.prepare("SELECT id,used_at FROM tickets WHERE booking_id=?").all(booking.id);
  const result = [];
  for (const t of tickets) {
    const qr = await QRCode.toDataURL(JSON.stringify({ ticketId: t.id, event: "Garba Night 3.0", eventDate: booking.event_date }));
    result.push({ ticketId: t.id, used: Boolean(t.used_at), qr });
  }
  res.json({ event: "Garba Night 3.0", eventDate: booking.event_date, passType: booking.pass_type, tickets: result });
});

// Staff-only endpoint. Configure a long random ADMIN_TOKEN; use this from a private scanning app.
app.post("/api/staff/scan", (req, res) => {
  const token = req.get("authorization")?.replace(/^Bearer\s+/i, "");
  if (!process.env.ADMIN_TOKEN || !token || !safeEqual(token, process.env.ADMIN_TOKEN)) return res.status(401).json({ error: "Unauthorized." });
  const { ticketId } = req.body || {};
  if (typeof ticketId !== "string" || ticketId.length > 100) return res.status(400).json({ error: "Invalid ticket ID." });
  const update = db.prepare("UPDATE tickets SET used_at=CURRENT_TIMESTAMP WHERE id=? AND used_at IS NULL").run(ticketId);
  if (update.changes !== 1) return res.status(409).json({ valid: false, message: "Ticket invalid, already used, or not found." });
  res.json({ valid: true, message: "Entry approved." });
});

app.listen(PORT, () => console.log(`Garba Night 3.0 server listening on port ${PORT}`));
