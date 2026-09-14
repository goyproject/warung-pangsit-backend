import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import { supabase } from './supabaseClient.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// Restriksi CORS: Hanya izinkan domain Frontend
const allowedOrigins = [
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  'http://localhost:3000'
];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Akses ditolak oleh CORS Policy!'));
    }
  },
  credentials: true
}));

app.use(express.json());

// ==========================================
// 1. ENDPOINT AUTHENTICATION & LOGIN
// ==========================================
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username dan password wajib diisi' });
  }

  try {
    const { data: user, error } = await supabase
      .from('wp_users')
      .select('*')
      .eq('username', username)
      .single();

    if (error || !user) {
      return res.status(401).json({ error: 'Username atau kata sandi salah' });
    }

    // Cek apakah password match (Mendukung Hash Bcrypt & Plaintext lama)
    let isMatch = false;
    if (user.password.startsWith('$2a$') || user.password.startsWith('$2b$')) {
      isMatch = await bcrypt.compare(password, user.password);
    } else {
      isMatch = user.password === password;
    }

    if (!isMatch) {
      return res.status(401).json({ error: 'Username atau kata sandi salah' });
    }

    res.json({
      message: 'Login berhasil',
      username: user.username,
      role: user.role
    });
  } catch (err) {
    res.status(500).json({ error: 'Terjadi kesalahan pada server' });
  }
});

// ==========================================
// 2. ENDPOINTS CATEGORIES
// ==========================================
app.get('/api/categories', async (req, res) => {
  const { data, error } = await supabase.from('wp_categories').select('*');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/categories', async (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: 'Nama kategori wajib diisi' });

  const { data, error } = await supabase.from('wp_categories').insert([{ name }]).select();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data[0]);
});

// ==========================================
// 3. ENDPOINTS PRODUCTS (MENU)
// ==========================================
app.get('/api/products', async (req, res) => {
  const { data, error } = await supabase.from('wp_products').select('*').order('id', { ascending: true });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/products', async (req, res) => {
  const { id, name, category, price, stock } = req.body;
  const newProduct = {
    id: id || Date.now(),
    name,
    category,
    price: Number(price),
    stock: Number(stock)
  };

  const { data, error } = await supabase.from('wp_products').insert([newProduct]).select();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data[0]);
});

app.put('/api/products/:id/stock', async (req, res) => {
  const { id } = req.params;
  const { stock } = req.body;

  const { data, error } = await supabase.from('wp_products').update({ stock }).eq('id', id).select();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data[0]);
});

app.delete('/api/products/:id', async (req, res) => {
  const { id } = req.params;
  const { error } = await supabase.from('wp_products').delete().eq('id', id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ message: 'Produk berhasil dihapus' });
});

// ==========================================
// 4. ENDPOINTS TRANSACTIONS (LAPORAN & BON)
// ==========================================
app.get('/api/transactions', async (req, res) => {
  const { data, error } = await supabase.from('wp_transactions').select('*').order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  
  const formatted = data.map(t => ({
    ...t,
    rawDate: t.raw_date,
    customerName: t.customer_name,
    paymentMethod: t.payment_method,
    paymentAmount: t.payment,
    items: typeof t.items === 'string' ? JSON.parse(t.items) : t.items
  }));
  res.json(formatted);
});

app.post('/api/transactions', async (req, res) => {
  const tx = req.body;
  const payload = {
    id: tx.id,
    date: tx.date,
    raw_date: tx.rawDate,
    customer_name: tx.customerName,
    payment_method: tx.paymentMethod,
    total: tx.total,
    payment: tx.payment,
    change: tx.change,
    status: tx.status,
    items: tx.items
  };

  const { data, error } = await supabase.from('wp_transactions').insert([payload]).select();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data[0]);
});

app.put('/api/transactions/:id/pay', async (req, res) => {
  const { id } = req.params;
  const { payment } = req.body;

  const { data, error } = await supabase
    .from('wp_transactions')
    .update({ status: 'Lunas', payment })
    .eq('id', id)
    .select();

  if (error) return res.status(500).json({ error: error.message });
  res.json(data[0]);
});

// Hapus Laporan Transaksi Spesifik
app.delete('/api/transactions/:id', async (req, res) => {
  const { id } = req.params;
  const { error } = await supabase.from('wp_transactions').delete().eq('id', id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ message: 'Transaksi berhasil dihapus' });
});

// ==========================================
// 5. ENDPOINTS USERS & KASIR (ENKRIPSI BCRYPT)
// ==========================================
app.get('/api/users', async (req, res) => {
  const { data, error } = await supabase.from('wp_users').select('id, username, role, created_at');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/users', async (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username dan password wajib diisi' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const { data, error } = await supabase
      .from('wp_users')
      .insert([{ username, password: hashedPassword, role: role || 'Kasir Cabang' }])
      .select('id, username, role');

    if (error) return res.status(500).json({ error: error.message });
    res.json(data[0]);
  } catch (err) {
    res.status(500).json({ error: 'Gagal memproses password' });
  }
});

app.delete('/api/users/:username', async (req, res) => {
  const { username } = req.params;
  const { error } = await supabase.from('wp_users').delete().eq('username', username);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ message: 'User berhasil dihapus' });
});

app.listen(PORT, () => {
  console.log(`🔒 Server Backend Aman berjalan di http://localhost:${PORT}`);
});