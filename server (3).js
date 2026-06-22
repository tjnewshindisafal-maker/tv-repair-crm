const express = require('express');
const cors    = require('cors');
const path    = require('path');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const { MongoClient, ObjectId } = require('mongodb');

const MONGO_URI  = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET || 'crm-secret-change-this';
const PORT       = process.env.PORT || 3000;

if (!MONGO_URI) { console.error('❌ MONGO_URI missing'); process.exit(1); }

const BRANDS = ['AN Electronics', 'QDigi Service Center', 'HS'];
const BRANCHES = [
  { id: 'AN-1', brand: 'AN Electronics',     name: 'AN Electronics Branch 1' },
  { id: 'AN-2', brand: 'AN Electronics',     name: 'AN Electronics Branch 2' },
  { id: 'AN-3', brand: 'AN Electronics',     name: 'AN Electronics Branch 3' },
  { id: 'QD-1', brand: 'QDigi Service Center', name: 'QDigi Branch 1' },
  { id: 'QD-2', brand: 'QDigi Service Center', name: 'QDigi Branch 2' },
  { id: 'QD-3', brand: 'QDigi Service Center', name: 'QDigi Branch 3' },
  { id: 'QD-4', brand: 'QDigi Service Center', name: 'QDigi Branch 4' },
  { id: 'HS-1', brand: 'HS', name: 'HS Branch 1' },
  { id: 'HS-2', brand: 'HS', name: 'HS Branch 2' },
  { id: 'HS-3', brand: 'HS', name: 'HS Branch 3' },
];

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

let db;
async function connectDB() {
  const client = new MongoClient(MONGO_URI);
  await client.connect();
  db = client.db('tv_repair_crm');
  console.log('✅ MongoDB connected');
  // indexes
  try { await db.collection('users').createIndex({ email: 1 }, { unique: true }); } catch(e) {}
  try { await db.collection('crm_customers').createIndex({ phone: 1 }, { unique: true }); } catch(e) {}
  await seedAdmin();
}

async function seedAdmin() {
  const exists = await db.collection('users').findOne({ role: 'admin' });
  if (!exists) {
    const hash = await bcrypt.hash('admin123', 10);
    await db.collection('users').insertOne({
      name: 'Admin', email: 'admin@tvrepair.com',
      password: hash, role: 'admin', createdAt: new Date()
    });
    console.log('👤 Default admin created: admin@tvrepair.com / admin123');
  }
}

function sanitize(s, max = 200) {
  if (!s) return '';
  return String(s).trim().slice(0, max).replace(/[<>]/g, '');
}

// ── AUTH MIDDLEWARE ───────────────────────────────────────────────────────────
function auth(req, res, next) {
  const token = req.headers['x-token'];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch(e) { res.status(401).json({ error: 'Invalid token' }); }
}

// ── LOGIN ─────────────────────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    const user = await db.collection('users').findOne({ email: email.toLowerCase().trim() });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ uid: user._id, name: user.name, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, name: user.name, role: user.role });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── CONFIG ────────────────────────────────────────────────────────────────────
app.get('/api/config', auth, (req, res) => {
  res.json({ brands: BRANDS, branches: BRANCHES });
});

// ── DASHBOARD ─────────────────────────────────────────────────────────────────
app.get('/api/dashboard', auth, async (req, res) => {
  try {
    const today = new Date(); today.setHours(0, 0, 0, 0);
    const [totalCalls, todayCalls, missedCalls, totalCustomers, activeJobs, completedJobs, pendingPay, todayRev] = await Promise.all([
      db.collection('crm_calls').countDocuments(),
      db.collection('crm_calls').countDocuments({ createdAt: { $gte: today } }),
      db.collection('crm_calls').countDocuments({ status: 'missed' }),
      db.collection('crm_customers').countDocuments(),
      db.collection('crm_jobs').countDocuments({ status: { $in: ['pending', 'in_progress'] } }),
      db.collection('crm_jobs').countDocuments({ status: 'completed' }),
      db.collection('crm_payments').aggregate([{ $match: { status: 'pending' } }, { $group: { _id: null, total: { $sum: '$amount' } } }]).toArray(),
      db.collection('crm_payments').aggregate([{ $match: { createdAt: { $gte: today }, status: 'paid' } }, { $group: { _id: null, total: { $sum: '$amount' } } }]).toArray(),
    ]);
    res.json({
      calls: { total: totalCalls, today: todayCalls, missed: missedCalls },
      customers: { total: totalCustomers },
      jobs: { active: activeJobs, completed: completedJobs },
      revenue: { pending: pendingPay[0]?.total || 0, today: todayRev[0]?.total || 0 }
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── CALLS ─────────────────────────────────────────────────────────────────────
app.get('/api/calls', auth, async (req, res) => {
  try {
    const { page = 1, limit = 20, branch, status, date } = req.query;
    const filter = {};
    if (branch) filter.branch = branch;
    if (status) filter.status = status;
    if (date) {
      const d = new Date(date); const next = new Date(d); next.setDate(d.getDate() + 1);
      filter.createdAt = { $gte: d, $lt: next };
    }
    const skip = (Number(page) - 1) * Number(limit);
    const [calls, total] = await Promise.all([
      db.collection('crm_calls').find(filter).sort({ createdAt: -1 }).skip(skip).limit(Number(limit)).toArray(),
      db.collection('crm_calls').countDocuments(filter),
    ]);
    res.json({ calls, total, page: Number(page), pages: Math.ceil(total / Number(limit)) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/calls', auth, async (req, res) => {
  try {
    const { customerName, phone, brand, branch, callType, notes, status } = req.body;
    if (!phone) return res.status(400).json({ error: 'Phone required' });
    const doc = {
      customerName: sanitize(customerName), phone: sanitize(phone, 15),
      brand: sanitize(brand), branch: sanitize(branch),
      callType: sanitize(callType) || 'inbound',
      notes: sanitize(notes, 500), status: sanitize(status) || 'received',
      agentId: req.user.uid, createdAt: new Date(),
    };
    const r = await db.collection('crm_calls').insertOne(doc);
    res.json({ _id: r.insertedId, ...doc });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/calls/:id', auth, async (req, res) => {
  try {
    const update = { updatedAt: new Date() };
    if (req.body.status) update.status = sanitize(req.body.status);
    if (req.body.notes) update.notes = sanitize(req.body.notes, 500);
    await db.collection('crm_calls').updateOne({ _id: new ObjectId(req.params.id) }, { $set: update });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── CUSTOMERS ─────────────────────────────────────────────────────────────────
app.get('/api/customers', auth, async (req, res) => {
  try {
    const { page = 1, limit = 20, search } = req.query;
    const filter = {};
    if (search) filter.$or = [{ name: { $regex: search, $options: 'i' } }, { phone: { $regex: search, $options: 'i' } }];
    const skip = (Number(page) - 1) * Number(limit);
    const [customers, total] = await Promise.all([
      db.collection('crm_customers').find(filter).sort({ createdAt: -1 }).skip(skip).limit(Number(limit)).toArray(),
      db.collection('crm_customers').countDocuments(filter),
    ]);
    res.json({ customers, total, page: Number(page), pages: Math.ceil(total / Number(limit)) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/customers', auth, async (req, res) => {
  try {
    const { name, phone, address, city } = req.body;
    if (!phone) return res.status(400).json({ error: 'Phone required' });
    const existing = await db.collection('crm_customers').findOne({ phone: sanitize(phone, 15) });
    if (existing) return res.json(existing);
    const doc = { name: sanitize(name), phone: sanitize(phone, 15), address: sanitize(address, 300), city: sanitize(city), createdAt: new Date() };
    const r = await db.collection('crm_customers').insertOne(doc);
    res.json({ _id: r.insertedId, ...doc });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/customers/:id', auth, async (req, res) => {
  try {
    const customer = await db.collection('crm_customers').findOne({ _id: new ObjectId(req.params.id) });
    if (!customer) return res.status(404).json({ error: 'Not found' });
    const [jobs, calls] = await Promise.all([
      db.collection('crm_jobs').find({ customerId: req.params.id }).sort({ createdAt: -1 }).toArray(),
      db.collection('crm_calls').find({ phone: customer.phone }).sort({ createdAt: -1 }).toArray(),
    ]);
    res.json({ customer, jobs, calls });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── JOB CARDS ─────────────────────────────────────────────────────────────────
app.get('/api/jobs', auth, async (req, res) => {
  try {
    const { page = 1, limit = 20, status, branch, brand } = req.query;
    const filter = {};
    if (status) filter.status = status;
    if (branch) filter.branch = branch;
    if (brand) filter.brand = brand;
    const skip = (Number(page) - 1) * Number(limit);
    const [jobs, total] = await Promise.all([
      db.collection('crm_jobs').find(filter).sort({ createdAt: -1 }).skip(skip).limit(Number(limit)).toArray(),
      db.collection('crm_jobs').countDocuments(filter),
    ]);
    res.json({ jobs, total, page: Number(page), pages: Math.ceil(total / Number(limit)) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/jobs', auth, async (req, res) => {
  try {
    const { customerId, customerName, phone, brand, branch, deviceType, deviceBrand, deviceModel, issue, estimatedCost, technicianName } = req.body;
    if (!phone) return res.status(400).json({ error: 'Phone required' });
    const jobNo = 'JOB-' + Date.now().toString(36).toUpperCase();
    const doc = {
      jobNo, customerId: sanitize(customerId), customerName: sanitize(customerName),
      phone: sanitize(phone, 15), brand: sanitize(brand), branch: sanitize(branch),
      deviceType: sanitize(deviceType) || 'TV', deviceBrand: sanitize(deviceBrand),
      deviceModel: sanitize(deviceModel), issue: sanitize(issue, 500),
      estimatedCost: Number(estimatedCost) || 0, technicianName: sanitize(technicianName),
      status: 'pending', createdAt: new Date(), updatedAt: new Date(),
    };
    const r = await db.collection('crm_jobs').insertOne(doc);
    res.json({ _id: r.insertedId, ...doc });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/jobs/:id', auth, async (req, res) => {
  try {
    const allowed = ['status', 'technicianName', 'estimatedCost', 'finalCost', 'issue', 'notes', 'deviceBrand', 'deviceModel'];
    const update = { updatedAt: new Date() };
    for (const key of allowed) {
      if (req.body[key] !== undefined)
        update[key] = typeof req.body[key] === 'number' ? Number(req.body[key]) : sanitize(String(req.body[key]), 500);
    }
    if (req.body.status === 'completed') update.completedAt = new Date();
    await db.collection('crm_jobs').updateOne({ _id: new ObjectId(req.params.id) }, { $set: update });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── PAYMENTS ──────────────────────────────────────────────────────────────────
app.get('/api/payments', auth, async (req, res) => {
  try {
    const { page = 1, limit = 20, status, branch } = req.query;
    const filter = {};
    if (status) filter.status = status;
    if (branch) filter.branch = branch;
    const skip = (Number(page) - 1) * Number(limit);
    const [payments, total] = await Promise.all([
      db.collection('crm_payments').find(filter).sort({ createdAt: -1 }).skip(skip).limit(Number(limit)).toArray(),
      db.collection('crm_payments').countDocuments(filter),
    ]);
    res.json({ payments, total, page: Number(page), pages: Math.ceil(total / Number(limit)) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/payments', auth, async (req, res) => {
  try {
    const { jobId, customerId, customerName, phone, amount, method, branch, brand, notes } = req.body;
    if (!amount || !jobId) return res.status(400).json({ error: 'jobId and amount required' });
    const doc = {
      jobId: sanitize(jobId), customerId: sanitize(customerId),
      customerName: sanitize(customerName), phone: sanitize(phone, 15),
      amount: Number(amount), method: sanitize(method) || 'cash',
      branch: sanitize(branch), brand: sanitize(brand),
      notes: sanitize(notes, 300), status: 'paid', createdAt: new Date(),
    };
    const r = await db.collection('crm_payments').insertOne(doc);
    try {
      await db.collection('crm_jobs').updateOne(
        { _id: new ObjectId(jobId) },
        { $set: { paymentStatus: 'paid', finalCost: Number(amount), updatedAt: new Date() } }
      );
    } catch(e) {}
    res.json({ _id: r.insertedId, ...doc });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── REPORTS ───────────────────────────────────────────────────────────────────
app.get('/api/reports', auth, async (req, res) => {
  try {
    const { from, to } = req.query;
    const fromDate = from ? new Date(from) : (() => { const d = new Date(); d.setDate(d.getDate() - 30); return d; })();
    const toDate = to ? new Date(to) : new Date(); toDate.setHours(23, 59, 59, 999);
    const [callsByBranch, jobsByStatus, revenueByBrand, dailyRevenue] = await Promise.all([
      db.collection('crm_calls').aggregate([{ $match: { createdAt: { $gte: fromDate, $lte: toDate } } }, { $group: { _id: '$branch', count: { $sum: 1 } } }, { $sort: { count: -1 } }]).toArray(),
      db.collection('crm_jobs').aggregate([{ $match: { createdAt: { $gte: fromDate, $lte: toDate } } }, { $group: { _id: '$status', count: { $sum: 1 } } }]).toArray(),
      db.collection('crm_payments').aggregate([{ $match: { createdAt: { $gte: fromDate, $lte: toDate }, status: 'paid' } }, { $group: { _id: '$brand', total: { $sum: '$amount' } } }, { $sort: { total: -1 } }]).toArray(),
      db.collection('crm_payments').aggregate([{ $match: { createdAt: { $gte: fromDate, $lte: toDate }, status: 'paid' } }, { $group: { _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } }, total: { $sum: '$amount' } } }, { $sort: { _id: 1 } }]).toArray(),
    ]);
    res.json({ callsByBranch, jobsByStatus, revenueByBrand, dailyRevenue });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── USERS (admin only) ────────────────────────────────────────────────────────
app.post('/api/users', auth, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    const { name, email, password, role } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    const hash = await bcrypt.hash(password, 10);
    const doc = { name: sanitize(name), email: email.toLowerCase().trim(), password: hash, role: role || 'agent', createdAt: new Date() };
    const r = await db.collection('users').insertOne(doc);
    res.json({ _id: r.insertedId, name: doc.name, email: doc.email, role: doc.role });
  } catch(e) {
    if (e.code === 11000) return res.status(400).json({ error: 'Email already exists' });
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/users', auth, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    const users = await db.collection('users').find({}, { projection: { password: 0 } }).toArray();
    res.json({ users });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── SERVE FRONTEND ────────────────────────────────────────────────────────────
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ── START ─────────────────────────────────────────────────────────────────────
app.listen(PORT, async () => {
  await connectDB();
  console.log(`🚀 TV Repair CRM running on port ${PORT}`);
});
