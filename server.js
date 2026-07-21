require('dotenv').config();

const express   = require('express');
const cors      = require('cors');
const path      = require('path');
const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const validator = require('validator');
const { MongoClient, ObjectId } = require('mongodb');

const MONGO_URI  = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const PORT       = process.env.PORT || 3000;
const BCRYPT_ROUNDS = 10;
const JWT_EXPIRY    = '7d';

if (!MONGO_URI || !JWT_SECRET || JWT_SECRET.length < 32) {
  console.error('FATAL: Set MONGO_URI and a JWT_SECRET (32+ chars) in your .env file.');
  process.exit(1);
}

let db;

// ── HELPERS ────────────────────────────────────────────────────────────────
function sanitize(s, maxLen) {
  if (!s) return '';
  return String(s).trim().slice(0, maxLen || 200).replace(/[<>]/g, '');
}
function createToken(userId) { return jwt.sign({ uid: userId }, JWT_SECRET, { expiresIn: JWT_EXPIRY }); }
function verifyToken(token) { try { return jwt.verify(token, JWT_SECRET); } catch (e) { return null; } }

const LEAD_SOURCES  = ['google_ads', 'gmb', 'myoperator', 'walkin', 'referral', 'website', 'other'];
const LEAD_STATUSES = ['new', 'contacted', 'converted', 'lost'];
const JOB_STATUSES  = ['pending', 'in_progress', 'waiting_parts', 'cost_sent', 'completed', 'delivered', 'cancelled'];

async function generateJobId(userId) {
  const count = await db.collection('jobs').countDocuments({ userId });
  return 'JOB-' + String(count + 1001).padStart(4, '0');
}

async function connectDB() {
  const client = new MongoClient(MONGO_URI, { serverSelectionTimeoutMS: 30000 });
  await client.connect();
  db = client.db('tvrepaircrm');
  console.log('MongoDB connected');
  try { await db.collection('users').createIndex({ email: 1 }, { unique: true }); } catch (e) {}
  try { await db.collection('locations').createIndex({ userId: 1 }); } catch (e) {}
  try { await db.collection('leads').createIndex({ userId: 1 }); } catch (e) {}
  try { await db.collection('jobs').createIndex({ userId: 1 }); } catch (e) {}
  try { await db.collection('jobs').createIndex({ jobId: 1 }); } catch (e) {}
  try { await db.collection('technicians').createIndex({ userId: 1 }); } catch (e) {}
}

// ── EXPRESS SETUP ────────────────────────────────────────────────────────────
const app = express();
app.set('trust proxy', 1);
app.use(cors());
app.use(express.json({ limit: '1mb' }));

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false,
  message: { ok: false, msg: 'Too many login attempts. Try again in 15 minutes.' } });
const signupLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 5, standardHeaders: true, legacyHeaders: false,
  message: { ok: false, msg: 'Too many signup attempts. Try again later.' } });
const apiLimiter = rateLimit({ windowMs: 60 * 1000, max: 120, standardHeaders: true, legacyHeaders: false,
  message: { ok: false, msg: 'Too many requests. Please slow down.' } });
app.use('/api/', apiLimiter);

app.use(express.static(path.join(__dirname, 'public')));

async function auth(req, res, next) {
  const token = req.headers['x-token'];
  if (!token) return res.json({ ok: false, msg: 'No token' });
  const decoded = verifyToken(token);
  if (!decoded) return res.json({ ok: false, msg: 'Invalid or expired token' });
  const user = await db.collection('users').findOne({ _id: new ObjectId(decoded.uid) });
  if (!user) return res.json({ ok: false, msg: 'Unauthorized' });
  req.user = user;
  req.userId = user._id.toString();
  next();
}

// ── AUTH ROUTES ──────────────────────────────────────────────────────────────
app.post('/api/signup', signupLimiter, async (req, res) => {
  try {
    let { name, email, password, business } = req.body;
    name = sanitize(name, 100);
    email = sanitize(email, 150).toLowerCase();
    business = sanitize(business, 150);

    if (!name || name.length < 2) return res.json({ ok: false, msg: 'Name required' });
    if (!validator.isEmail(email)) return res.json({ ok: false, msg: 'Invalid email' });
    if (!password || password.length < 6) return res.json({ ok: false, msg: 'Password must be at least 6 characters' });

    const existing = await db.collection('users').findOne({ email });
    if (existing) return res.json({ ok: false, msg: 'Email already registered' });

    const hashedPass = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const result = await db.collection('users').insertOne({
      name, email, pass: hashedPass, business: business || name,
      createdAt: new Date()
    });
    const token = createToken(result.insertedId.toString());
    res.json({ ok: true, token, name, business: business || name });
  } catch (e) { res.json({ ok: false, msg: 'Signup failed. Try again.' }); }
});

app.post('/api/login', loginLimiter, async (req, res) => {
  try {
    let { email, password } = req.body;
    email = sanitize(email, 150).toLowerCase();
    if (!validator.isEmail(email)) return res.json({ ok: false, msg: 'Invalid email' });
    if (!password) return res.json({ ok: false, msg: 'Password required' });

    const user = await db.collection('users').findOne({ email });
    if (!user) return res.json({ ok: false, msg: 'Wrong email or password' });

    const match = await bcrypt.compare(password, user.pass);
    if (!match) return res.json({ ok: false, msg: 'Wrong email or password' });

    const token = createToken(user._id.toString());
    res.json({ ok: true, token, name: user.name, business: user.business });
  } catch (e) { res.json({ ok: false, msg: 'Login failed' }); }
});

app.get('/api/me', auth, async (req, res) => {
  res.json({ ok: true, user: { id: req.user._id, name: req.user.name, email: req.user.email, business: req.user.business } });
});

// ── LOCATIONS ────────────────────────────────────────────────────────────────
app.get('/api/locations', auth, async (req, res) => {
  const locations = await db.collection('locations').find({ userId: req.userId }).sort({ createdAt: 1 }).toArray();
  res.json({ ok: true, locations });
});

app.post('/api/locations', auth, async (req, res) => {
  try {
    const name = sanitize(req.body.name, 100);
    const address = sanitize(req.body.address, 300);
    const phone = sanitize(req.body.phone, 15);
    if (!name) return res.json({ ok: false, msg: 'Location name required' });
    const count = await db.collection('locations').countDocuments({ userId: req.userId });
    if (count >= 50) return res.json({ ok: false, msg: 'Location limit reached (50 max)' });
    const doc = { userId: req.userId, name, address, phone, createdAt: new Date() };
    const r = await db.collection('locations').insertOne(doc);
    res.json({ ok: true, location: { ...doc, _id: r.insertedId } });
  } catch (e) { res.json({ ok: false, msg: e.message }); }
});

app.put('/api/locations/:id', auth, async (req, res) => {
  try {
    if (!ObjectId.isValid(req.params.id)) return res.json({ ok: false, msg: 'Invalid ID' });
    const updates = {};
    if (req.body.name !== undefined) updates.name = sanitize(req.body.name, 100);
    if (req.body.address !== undefined) updates.address = sanitize(req.body.address, 300);
    if (req.body.phone !== undefined) updates.phone = sanitize(req.body.phone, 15);
    if (updates.name === '') return res.json({ ok: false, msg: 'Location name required' });
    await db.collection('locations').updateOne({ _id: new ObjectId(req.params.id), userId: req.userId }, { $set: updates });
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, msg: e.message }); }
});

app.delete('/api/locations/:id', auth, async (req, res) => {
  try {
    if (!ObjectId.isValid(req.params.id)) return res.json({ ok: false, msg: 'Invalid ID' });
    await db.collection('locations').deleteOne({ _id: new ObjectId(req.params.id), userId: req.userId });
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, msg: e.message }); }
});

// ── LEADS / CALLS ──────────────────────────────────────────────────────────────
app.get('/api/leads', auth, async (req, res) => {
  try {
    const query = { userId: req.userId };
    const location = sanitize(req.query.location, 100);
    const source = sanitize(req.query.source, 30);
    const status = sanitize(req.query.status, 20);
    const search = sanitize(req.query.search, 100);
    if (location) query.location = location;
    if (source && LEAD_SOURCES.indexOf(source) !== -1) query.source = source;
    if (status && LEAD_STATUSES.indexOf(status) !== -1) query.status = status;
    if (search) {
      const safe = search.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      query.$or = [{ name: { $regex: safe, $options: 'i' } }, { phone: { $regex: safe, $options: 'i' } }];
    }
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const total = await db.collection('leads').countDocuments(query);
    const leads = await db.collection('leads').find(query).sort({ createdAt: -1 }).skip((page - 1) * 50).limit(50).toArray();
    res.json({ ok: true, leads, total });
  } catch (e) { res.json({ ok: false, msg: e.message }); }
});

app.get('/api/leads/stats', auth, async (req, res) => {
  try {
    const all = await db.collection('leads').find({ userId: req.userId }).toArray();
    const total = all.length;
    const byStatus = {}, byLocation = {}, bySource = {};
    all.forEach(l => {
      byStatus[l.status] = (byStatus[l.status] || 0) + 1;
      const loc = l.location || 'Unspecified';
      if (!byLocation[loc]) byLocation[loc] = { total: 0, converted: 0 };
      byLocation[loc].total++;
      if (l.status === 'converted') byLocation[loc].converted++;
      bySource[l.source || 'other'] = (bySource[l.source || 'other'] || 0) + 1;
    });
    const converted = byStatus.converted || 0;
    res.json({ ok: true, total, converted, convRate: total ? Math.round((converted / total) * 100) : 0, byStatus, byLocation, bySource });
  } catch (e) { res.json({ ok: false, msg: e.message }); }
});

app.post('/api/leads', auth, async (req, res) => {
  try {
    const name = sanitize(req.body.name, 100);
    const phone = sanitize(req.body.phone, 15);
    const location = sanitize(req.body.location, 100);
    const source = LEAD_SOURCES.indexOf(req.body.source) !== -1 ? req.body.source : 'other';
    const notes = sanitize(req.body.notes, 1000);
    if (!name || !phone) return res.json({ ok: false, msg: 'Name and phone required' });
    const doc = { userId: req.userId, name, phone, location, source, status: 'new', notes, jobId: null, createdAt: new Date(), updatedAt: new Date() };
    const r = await db.collection('leads').insertOne(doc);
    res.json({ ok: true, lead: { ...doc, _id: r.insertedId } });
  } catch (e) { res.json({ ok: false, msg: e.message }); }
});

app.post('/api/leads/import', auth, async (req, res) => {
  try {
    const rows = req.body.rows;
    if (!Array.isArray(rows) || !rows.length) return res.json({ ok: false, msg: 'No rows to import' });
    if (rows.length > 2000) return res.json({ ok: false, msg: 'Max 2000 rows per import' });
    const docs = [];
    for (const row of rows) {
      const name = sanitize(row.name, 100);
      const phone = sanitize(row.phone, 15);
      if (!name || !phone) continue;
      const location = sanitize(row.location, 100);
      const source = LEAD_SOURCES.indexOf(row.source) !== -1 ? row.source : 'myoperator';
      const notes = sanitize(row.notes, 1000);
      let createdAt = new Date();
      if (row.createdAt) { const d = new Date(row.createdAt); if (!isNaN(d.getTime())) createdAt = d; }
      docs.push({ userId: req.userId, name, phone, location, source, status: 'new', notes, jobId: null, createdAt, updatedAt: new Date() });
    }
    if (!docs.length) return res.json({ ok: false, msg: 'No valid rows found (Name + Phone required)' });
    await db.collection('leads').insertMany(docs);
    res.json({ ok: true, imported: docs.length });
  } catch (e) { res.json({ ok: false, msg: e.message }); }
});

app.put('/api/leads/:id', auth, async (req, res) => {
  try {
    if (!ObjectId.isValid(req.params.id)) return res.json({ ok: false, msg: 'Invalid ID' });
    const updates = { updatedAt: new Date() };
    if (req.body.status !== undefined && LEAD_STATUSES.indexOf(req.body.status) !== -1) updates.status = req.body.status;
    if (req.body.notes !== undefined) updates.notes = sanitize(req.body.notes, 1000);
    if (req.body.location !== undefined) updates.location = sanitize(req.body.location, 100);
    if (req.body.source !== undefined && LEAD_SOURCES.indexOf(req.body.source) !== -1) updates.source = req.body.source;
    await db.collection('leads').updateOne({ _id: new ObjectId(req.params.id), userId: req.userId }, { $set: updates });
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, msg: e.message }); }
});

app.delete('/api/leads/:id', auth, async (req, res) => {
  try {
    if (!ObjectId.isValid(req.params.id)) return res.json({ ok: false, msg: 'Invalid ID' });
    await db.collection('leads').deleteOne({ _id: new ObjectId(req.params.id), userId: req.userId });
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, msg: e.message }); }
});

app.put('/api/leads/:id/link-job', auth, async (req, res) => {
  try {
    if (!ObjectId.isValid(req.params.id)) return res.json({ ok: false, msg: 'Invalid ID' });
    const jobId = sanitize(req.body.jobId, 30);
    if (!jobId) return res.json({ ok: false, msg: 'jobId required' });
    await db.collection('leads').updateOne({ _id: new ObjectId(req.params.id), userId: req.userId }, { $set: { status: 'converted', jobId, updatedAt: new Date() } });
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, msg: e.message }); }
});

// ── TECHNICIANS ────────────────────────────────────────────────────────────────
app.get('/api/technicians', auth, async (req, res) => {
  const technicians = await db.collection('technicians').find({ userId: req.userId }).toArray();
  res.json({ ok: true, technicians });
});

app.post('/api/technicians', auth, async (req, res) => {
  try {
    const name = sanitize(req.body.name, 100);
    const phone = sanitize(req.body.phone, 15);
    const skill = sanitize(req.body.skill, 200);
    if (!name || !phone) return res.json({ ok: false, msg: 'Name and phone required' });
    await db.collection('technicians').insertOne({ userId: req.userId, name, phone, skill, jobsCompleted: 0, createdAt: new Date() });
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, msg: e.message }); }
});

app.delete('/api/technicians/:id', auth, async (req, res) => {
  try {
    if (!ObjectId.isValid(req.params.id)) return res.json({ ok: false, msg: 'Invalid ID' });
    await db.collection('technicians').deleteOne({ _id: new ObjectId(req.params.id), userId: req.userId });
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, msg: e.message }); }
});

// ── JOBS ─────────────────────────────────────────────────────────────────────
app.get('/api/jobs', auth, async (req, res) => {
  try {
    const status = sanitize(req.query.status, 30);
    const location = sanitize(req.query.location, 100);
    const search = sanitize(req.query.search, 100);
    const query = { userId: req.userId };
    if (status) query.status = status;
    if (location) query.location = location;
    if (search) {
      const safe = search.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      query.$or = [
        { jobId: { $regex: safe, $options: 'i' } },
        { customerName: { $regex: safe, $options: 'i' } },
        { customerPhone: { $regex: safe, $options: 'i' } }
      ];
    }
    const jobs = await db.collection('jobs').find(query).sort({ createdAt: -1 }).limit(500).toArray();
    res.json({ ok: true, jobs });
  } catch (e) { res.json({ ok: false, msg: e.message }); }
});

app.post('/api/jobs', auth, async (req, res) => {
  try {
    let { customerName, customerPhone, serviceType, description, deviceModel, priority, location } = req.body;
    customerName = sanitize(customerName, 100);
    customerPhone = sanitize(customerPhone, 15);
    serviceType = sanitize(serviceType, 100) || 'General';
    description = sanitize(description, 1000);
    deviceModel = sanitize(deviceModel, 200);
    location = sanitize(location, 100);
    priority = ['normal', 'urgent', 'vip'].indexOf(priority) !== -1 ? priority : 'normal';
    if (!customerName || !customerPhone) return res.json({ ok: false, msg: 'Customer name and phone required' });

    const jobId = await generateJobId(req.userId);
    const job = {
      jobId, userId: req.userId, customerName, customerPhone, serviceType, description, deviceModel,
      priority, location, status: 'pending',
      statusHistory: [{ status: 'pending', time: new Date(), note: 'Created' }],
      cost: null, technicianId: null, technicianName: null,
      createdAt: new Date(), updatedAt: new Date()
    };
    await db.collection('jobs').insertOne(job);
    res.json({ ok: true, job });
  } catch (e) { res.json({ ok: false, msg: e.message }); }
});

app.put('/api/jobs/:id/status', auth, async (req, res) => {
  try {
    const status = sanitize(req.body.status, 30);
    const note = sanitize(req.body.note, 500);
    if (JOB_STATUSES.indexOf(status) === -1) return res.json({ ok: false, msg: 'Invalid status' });
    const jobId = sanitize(req.params.id, 30);
    await db.collection('jobs').updateOne(
      { jobId, userId: req.userId },
      { $set: { status, updatedAt: new Date() }, $push: { statusHistory: { status, time: new Date(), note } } }
    );
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, msg: e.message }); }
});

app.put('/api/jobs/:id/cost', auth, async (req, res) => {
  try {
    const cost = Math.max(0, parseFloat(req.body.cost) || 0);
    const costNote = sanitize(req.body.costNote, 500);
    const jobId = sanitize(req.params.id, 30);
    await db.collection('jobs').updateOne(
      { jobId, userId: req.userId },
      { $set: { cost, costNote, status: 'cost_sent', updatedAt: new Date() }, $push: { statusHistory: { status: 'cost_sent', time: new Date(), note: 'Cost: ' + cost } } }
    );
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, msg: e.message }); }
});

app.put('/api/jobs/:id/technician', auth, async (req, res) => {
  try {
    const techId = sanitize(req.body.technicianId, 30);
    if (!techId || !ObjectId.isValid(techId)) return res.json({ ok: false, msg: 'Invalid technician ID' });
    const tech = await db.collection('technicians').findOne({ _id: new ObjectId(techId), userId: req.userId });
    if (!tech) return res.json({ ok: false, msg: 'Technician not found' });
    const jobId = sanitize(req.params.id, 30);
    await db.collection('jobs').updateOne({ jobId, userId: req.userId }, { $set: { technicianId: techId, technicianName: tech.name, updatedAt: new Date() } });
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, msg: e.message }); }
});

// ── CUSTOMERS (aggregated from jobs) ──────────────────────────────────────────
app.get('/api/customers', auth, async (req, res) => {
  try {
    const search = sanitize(req.query.search, 100);
    const query = { userId: req.userId };
    if (search) {
      const safe = search.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      query.$or = [{ customerName: { $regex: safe, $options: 'i' } }, { customerPhone: { $regex: safe, $options: 'i' } }];
    }
    const customers = await db.collection('jobs').aggregate([
      { $match: query },
      { $group: { _id: '$customerPhone', name: { $last: '$customerName' }, phone: { $last: '$customerPhone' }, totalJobs: { $sum: 1 }, lastJob: { $max: '$createdAt' } } },
      { $sort: { lastJob: -1 } },
      { $limit: 500 }
    ]).toArray();
    res.json({ ok: true, customers });
  } catch (e) { res.json({ ok: false, msg: e.message }); }
});

app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ ok: false, msg: 'Not found' });
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

connectDB().then(() => {
  app.listen(PORT, () => console.log('tv-repair-crm running on port ' + PORT));
}).catch(e => { console.error('MongoDB connection failed:', e.message); process.exit(1); });
