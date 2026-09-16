import express from 'express';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { db, testConnection, handleFirestoreError, OperationType } from './firebase.js';
import { collection, getDocs, doc, setDoc, deleteDoc } from 'firebase/firestore';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 3000;
const HOST = '0.0.0.0';

const DATA_DIR = path.join(__dirname, 'data');
const PRODUCTS_FILE = path.join(DATA_DIR, 'products.json');
const DEFAULT_PRODUCTS_FILE = path.join(DATA_DIR, 'default_products.json');
const ADMIN_FILE = path.join(DATA_DIR, 'admin.json');
const ADMINS_FILE = path.join(DATA_DIR, 'admins.json');
const BOOTSTRAPPED_OWNER_EMAIL = 'mackson.weiber13@gmail.com';

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// In-memory active sessions: token -> { username, expiresAt }
const sessions = new Map();

function hashPassword(password) {
  return crypto.createHash('sha256').update(String(password).trim()).digest('hex');
}

function getAuthorizedAdmins() {
  try {
    if (fs.existsSync(ADMINS_FILE)) {
      const data = JSON.parse(fs.readFileSync(ADMINS_FILE, 'utf-8'));
      if (Array.isArray(data) && data.length > 0) {
        const hasOwner = data.some(a => a.email && a.email.toLowerCase() === BOOTSTRAPPED_OWNER_EMAIL.toLowerCase());
        if (!hasOwner) {
          data.unshift({
            id: 'owner-mackson',
            email: BOOTSTRAPPED_OWNER_EMAIL,
            name: 'Mackson Weiber',
            role: 'superadmin',
            status: 'active',
            isOwner: true,
            createdAt: '2026-09-14T20:00:00.000Z',
            addedBy: 'Sistema (Proprietário)'
          });
          saveAuthorizedAdmins(data);
        }
        return data;
      }
    }
  } catch (err) {
    console.error('Erro ao ler administradores autorizados:', err);
  }

  const defaultAdmins = [
    {
      id: 'owner-mackson',
      email: BOOTSTRAPPED_OWNER_EMAIL,
      name: 'Mackson Weiber',
      role: 'superadmin',
      status: 'active',
      isOwner: true,
      createdAt: '2026-09-14T20:00:00.000Z',
      addedBy: 'Sistema (Proprietário)'
    }
  ];
  saveAuthorizedAdmins(defaultAdmins);
  return defaultAdmins;
}

function saveAuthorizedAdmins(admins) {
  try {
    fs.writeFileSync(ADMINS_FILE, JSON.stringify(admins, null, 2), 'utf-8');
    return true;
  } catch (err) {
    console.error('Erro ao salvar administradores autorizados:', err);
    return false;
  }
}

function findAdminByEmail(email) {
  if (!email) return null;
  const list = getAuthorizedAdmins();
  const normalized = email.trim().toLowerCase();
  return list.find(a => a.email && a.email.trim().toLowerCase() === normalized) || null;
}

function getAdminCredentials() {
  try {
    if (fs.existsSync(ADMIN_FILE)) {
      const data = JSON.parse(fs.readFileSync(ADMIN_FILE, 'utf-8'));
      if (data && data.username && data.passwordHash) {
        return {
          username: data.username,
          passwordHash: data.passwordHash
        };
      }
    }
  } catch (err) {
    console.error('Erro ao ler credenciais do admin:', err);
  }

  const defaultUser = process.env.ADMIN_USERNAME || 'admin';
  const defaultPass = process.env.ADMIN_PASSWORD || 'janybeauty2026';
  return {
    username: defaultUser,
    passwordHash: hashPassword(defaultPass)
  };
}

function saveAdminCredentials(username, password) {
  const data = {
    username: username.trim(),
    passwordHash: hashPassword(password),
    updatedAt: new Date().toISOString()
  };
  fs.writeFileSync(ADMIN_FILE, JSON.stringify(data, null, 2), 'utf-8');
  return data;
}

function getProducts() {
  try {
    if (fs.existsSync(PRODUCTS_FILE)) {
      const content = fs.readFileSync(PRODUCTS_FILE, 'utf-8');
      const parsed = JSON.parse(content);
      if (Array.isArray(parsed)) {
        return parsed;
      }
    }
    if (fs.existsSync(DEFAULT_PRODUCTS_FILE)) {
      const content = fs.readFileSync(DEFAULT_PRODUCTS_FILE, 'utf-8');
      const parsed = JSON.parse(content);
      if (Array.isArray(parsed)) {
        fs.writeFileSync(PRODUCTS_FILE, JSON.stringify(parsed, null, 2), 'utf-8');
        return parsed;
      }
    }
  } catch (err) {
    console.error('Erro ao carregar produtos:', err);
  }
  return [];
}

function saveProducts(products) {
  fs.writeFileSync(PRODUCTS_FILE, JSON.stringify(products, null, 2), 'utf-8');
}

// Middleware for parsing JSON with ample capacity for base64 images
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, HEAD, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }
  next();
});

// Authentication middleware for admin routes
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || '';
  let token = '';
  if (authHeader.startsWith('Bearer ')) {
    token = authHeader.substring(7).trim();
  } else if (req.headers['x-admin-token']) {
    token = String(req.headers['x-admin-token']).trim();
  } else if (req.query && req.query.token) {
    token = String(req.query.token).trim();
  }

  if (!token || !sessions.has(token)) {
    return res.status(401).json({
      success: false,
      error: 'Não autorizado. Por favor, realize o login com usuário e senha.'
    });
  }

  const session = sessions.get(token);
  if (session.expiresAt < Date.now()) {
    sessions.delete(token);
    return res.status(401).json({
      success: false,
      error: 'Sua sessão expirou. Por favor, entre novamente com suas credenciais.'
    });
  }

  req.adminUser = session.username;
  req.sessionToken = token;
  next();
}

// ----------------- API ROUTES ----------------- //

// Login endpoint (Autenticação por E-mail Autorizado)
app.post('/api/admin/login', (req, res) => {
  const { email, username } = req.body || {};
  const rawEmail = (email || username || '').trim().toLowerCase();

  if (!rawEmail) {
    return res.status(400).json({
      success: false,
      error: 'Por favor, informe seu e-mail cadastrado.'
    });
  }

  const isOwner = rawEmail === BOOTSTRAPPED_OWNER_EMAIL.toLowerCase();
  const existingAdmin = findAdminByEmail(rawEmail);

  if (!isOwner && (!existingAdmin || existingAdmin.status !== 'active')) {
    return res.status(403).json({
      success: false,
      error: `Acesso negado para o e-mail "${rawEmail}". Este e-mail não possui autorização de administrador ativa. Solicite a inclusão ao proprietário.`
    });
  }

  // Update last login
  const admins = getAuthorizedAdmins();
  const adminIdx = admins.findIndex(a => a.email && a.email.toLowerCase() === rawEmail);
  let adminName = rawEmail.split('@')[0];
  let adminRole = isOwner ? 'superadmin' : 'admin';

  if (adminIdx >= 0) {
    admins[adminIdx].lastLoginAt = new Date().toISOString();
    adminName = admins[adminIdx].name || adminName;
    adminRole = admins[adminIdx].role || adminRole;
    saveAuthorizedAdmins(admins);
  }

  // Create session token valid for 7 days
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000;
  sessions.set(token, {
    username: adminName,
    email: rawEmail,
    role: adminRole,
    expiresAt
  });

  return res.json({
    success: true,
    token,
    user: {
      username: adminName,
      email: rawEmail,
      role: adminRole
    },
    message: `Acesso autorizado com sucesso para ${rawEmail}!`
  });
});

// Firebase Google Login endpoint
app.post('/api/admin/firebase-login', async (req, res) => {
  const { email, uid, displayName } = req.body || {};
  if (!email) {
    return res.status(400).json({
      success: false,
      error: 'E-mail da conta Google não informado.'
    });
  }

  const normalizedEmail = email.trim().toLowerCase();
  const isOwner = normalizedEmail === BOOTSTRAPPED_OWNER_EMAIL.toLowerCase();
  const existingAdmin = findAdminByEmail(normalizedEmail);

  if (!isOwner && (!existingAdmin || existingAdmin.status !== 'active')) {
    return res.status(403).json({
      success: false,
      error: `Acesso negado para o e-mail ${email}. Este e-mail não possui autorização ativa. Solicite a inclusão na aba Administradores.`
    });
  }

  // Update last login and uid if available
  const admins = getAuthorizedAdmins();
  const adminIdx = admins.findIndex(a => a.email && a.email.toLowerCase() === normalizedEmail);
  if (adminIdx >= 0) {
    admins[adminIdx].lastLoginAt = new Date().toISOString();
    if (uid) admins[adminIdx].firebaseUid = uid;
    if (displayName && !admins[adminIdx].name) admins[adminIdx].name = displayName;
    saveAuthorizedAdmins(admins);

    // Sync UID to Firestore admins collection for Firestore Security Rules
    try {
      if (uid) {
        await setDoc(doc(db, 'admins', uid), {
          email: normalizedEmail,
          name: admins[adminIdx].name || displayName || '',
          role: admins[adminIdx].role || 'admin',
          status: 'active',
          isOwner: admins[adminIdx].isOwner || false,
          updatedAt: new Date().toISOString()
        }, { merge: true });
      }
      await setDoc(doc(db, 'admins', normalizedEmail), {
        email: normalizedEmail,
        name: admins[adminIdx].name || displayName || '',
        role: admins[adminIdx].role || 'admin',
        status: 'active',
        uid: uid || '',
        isOwner: admins[adminIdx].isOwner || false,
        updatedAt: new Date().toISOString()
      }, { merge: true });
    } catch (fsErr) {
      console.warn('Sync admin login to Firestore:', fsErr.message);
    }
  }

  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000;
  const username = displayName ? `${displayName} (${email})` : email;
  sessions.set(token, {
    username,
    email: normalizedEmail,
    firebaseUid: uid,
    expiresAt
  });

  return res.json({
    success: true,
    token,
    user: {
      username,
      email: normalizedEmail,
      role: existingAdmin?.role || (isOwner ? 'superadmin' : 'admin')
    },
    message: 'Autenticado com sucesso via Firebase Google Auth!'
  });
});

// Firebase Status and configuration info
app.get('/api/firebase/status', async (req, res) => {
  let isHealthy = false;
  try {
    isHealthy = await testConnection();
  } catch (e) {}

  res.json({
    status: isHealthy ? 'connected' : 'active',
    connected: true,
    projectId: 'gen-lang-client-0932299286',
    databaseId: 'ai-studio-janebeauty-422c894f-45b5-461d-8c9f-6c5fc596e85f',
    region: 'us-west2',
    product: 'Firebase Firestore',
    bootstrappedAdmin: 'mackson.weiber13@gmail.com'
  });
});

// Check current authentication session
app.get('/api/admin/me', requireAuth, (req, res) => {
  return res.json({
    success: true,
    user: {
      username: req.adminUser
    }
  });
});

// Logout endpoint
app.post('/api/admin/logout', requireAuth, (req, res) => {
  if (req.sessionToken) {
    sessions.delete(req.sessionToken);
  }
  return res.json({
    success: true,
    message: 'Sessão encerrada com sucesso.'
  });
});

// Change admin credentials
app.post('/api/admin/change-credentials', requireAuth, (req, res) => {
  const { currentPassword, newUsername, newPassword } = req.body || {};
  if (!currentPassword || !newPassword) {
    return res.status(400).json({
      success: false,
      error: 'A senha atual e a nova senha são obrigatórias.'
    });
  }

  if (newPassword.length < 6) {
    return res.status(400).json({
      success: false,
      error: 'A nova senha deve conter no mínimo 6 caracteres.'
    });
  }

  const creds = getAdminCredentials();
  if (hashPassword(currentPassword) !== creds.passwordHash) {
    return res.status(401).json({
      success: false,
      error: 'A senha atual informada está incorreta.'
    });
  }

  const updatedUsername = (newUsername && newUsername.trim()) ? newUsername.trim() : creds.username;
  saveAdminCredentials(updatedUsername, newPassword);

  // Update session
  sessions.set(req.sessionToken, {
    username: updatedUsername,
    expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000
  });

  return res.json({
    success: true,
    message: 'Credenciais atualizadas com sucesso!',
    user: {
      username: updatedUsername
    }
  });
});

// ================= ADMINS MANAGEMENT API ================= //

// List all authorized administrators
app.get('/api/admin/admins', requireAuth, (req, res) => {
  const admins = getAuthorizedAdmins();
  return res.json({
    success: true,
    admins,
    bootstrappedOwner: BOOTSTRAPPED_OWNER_EMAIL
  });
});

// Add a new authorized admin email
app.post('/api/admin/admins', requireAuth, async (req, res) => {
  const { email, name, role } = req.body || {};
  if (!email || typeof email !== 'string') {
    return res.status(400).json({
      success: false,
      error: 'O e-mail é obrigatório.'
    });
  }

  const normalizedEmail = email.trim().toLowerCase();
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(normalizedEmail)) {
    return res.status(400).json({
      success: false,
      error: 'Formato de e-mail inválido. Digite um e-mail válido (ex: usuario@gmail.com).'
    });
  }

  const validRoles = ['admin', 'editor'];
  const assignedRole = validRoles.includes(role) ? role : 'admin';
  const admins = getAuthorizedAdmins();

  const existing = admins.find(a => a.email && a.email.toLowerCase() === normalizedEmail);
  if (existing) {
    return res.status(400).json({
      success: false,
      error: `O e-mail ${normalizedEmail} já está cadastrado na lista de administradores.`
    });
  }

  const newAdmin = {
    id: 'adm-' + crypto.randomBytes(6).toString('hex'),
    email: normalizedEmail,
    name: (name && typeof name === 'string') ? name.trim() : normalizedEmail.split('@')[0],
    role: assignedRole,
    status: 'active',
    isOwner: normalizedEmail === BOOTSTRAPPED_OWNER_EMAIL.toLowerCase(),
    createdAt: new Date().toISOString(),
    addedBy: req.adminUser || 'Admin'
  };

  admins.push(newAdmin);
  saveAuthorizedAdmins(admins);

  // Sync to Firestore collection 'admins'
  try {
    await setDoc(doc(db, 'admins', normalizedEmail), {
      email: normalizedEmail,
      name: newAdmin.name,
      role: newAdmin.role,
      status: 'active',
      isOwner: newAdmin.isOwner,
      createdAt: newAdmin.createdAt,
      addedBy: newAdmin.addedBy,
      updatedAt: new Date().toISOString()
    }, { merge: true });
    console.log(`🔥 Administrador ${normalizedEmail} sincronizado no Firestore`);
  } catch (fsErr) {
    console.warn('Erro ao sincronizar admin no Firestore:', fsErr.message);
  }

  return res.json({
    success: true,
    message: `E-mail ${normalizedEmail} autorizado com sucesso como ${assignedRole === 'admin' ? 'Administrador' : 'Editor'}!`,
    admin: newAdmin
  });
});

// Toggle admin status (active / inactive)
app.patch('/api/admin/admins/:id/toggle', requireAuth, async (req, res) => {
  const { id } = req.params;
  const admins = getAuthorizedAdmins();
  const idx = admins.findIndex(a => a.id === id || a.email === id);

  if (idx === -1) {
    return res.status(404).json({
      success: false,
      error: 'Administrador não encontrado.'
    });
  }

  const target = admins[idx];
  if (target.isOwner || (target.email && target.email.toLowerCase() === BOOTSTRAPPED_OWNER_EMAIL.toLowerCase())) {
    return res.status(403).json({
      success: false,
      error: 'A conta do proprietário principal não pode ser desativada.'
    });
  }

  target.status = target.status === 'active' ? 'inactive' : 'active';
  target.updatedAt = new Date().toISOString();
  saveAuthorizedAdmins(admins);

  // Sync status to Firestore
  try {
    await setDoc(doc(db, 'admins', target.email), {
      status: target.status,
      updatedAt: target.updatedAt
    }, { merge: true });
  } catch (fsErr) {
    console.warn('Erro ao atualizar status do admin no Firestore:', fsErr.message);
  }

  return res.json({
    success: true,
    message: `Status do administrador ${target.email} alterado para: ${target.status === 'active' ? 'Ativo' : 'Inativo'}.`,
    admin: target
  });
});

// Delete / revoke admin access
app.delete('/api/admin/admins/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  const admins = getAuthorizedAdmins();
  const idx = admins.findIndex(a => a.id === id || a.email === id);

  if (idx === -1) {
    return res.status(404).json({
      success: false,
      error: 'Administrador não encontrado.'
    });
  }

  const target = admins[idx];
  if (target.isOwner || (target.email && target.email.toLowerCase() === BOOTSTRAPPED_OWNER_EMAIL.toLowerCase())) {
    return res.status(403).json({
      success: false,
      error: 'A conta do proprietário principal (Superadmin) não pode ser removida.'
    });
  }

  admins.splice(idx, 1);
  saveAuthorizedAdmins(admins);

  // Delete from Firestore
  try {
    await deleteDoc(doc(db, 'admins', target.email));
    if (target.firebaseUid) {
      await deleteDoc(doc(db, 'admins', target.firebaseUid));
    }
    console.log(`🔥 Administrador ${target.email} removido do Firestore`);
  } catch (fsErr) {
    console.warn('Erro ao deletar admin do Firestore:', fsErr.message);
  }

  return res.json({
    success: true,
    message: `Acesso do administrador ${target.email} revogado e removido com sucesso.`
  });
});

// Public: Get all products (reading from Firestore with local fallback)
app.get('/api/products', async (req, res) => {
  try {
    const colRef = collection(db, 'products');
    const snap = await getDocs(colRef);
    if (!snap.empty) {
      const prods = [];
      snap.forEach(docSnap => {
        prods.push(docSnap.data());
      });
      // Sort: newest first if createdAt exists
      prods.sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
      return res.json(prods);
    }
  } catch (err) {
    console.warn('Firestore fallback to local cache:', err ? err.message : '');
  }

  const products = getProducts();
  res.json(products);
});

// Protected: Create a new product
app.post('/api/products', requireAuth, (req, res) => {
  const { title, tag, description, price, rating, image, alt, whatsapp, buyLink } = req.body || {};

  if (!title || !title.trim()) {
    return res.status(400).json({
      success: false,
      error: 'O título do produto é obrigatório.'
    });
  }

  const products = getProducts();
  const id = 'prod_' + Date.now();
  const cleanTitle = title.trim();

  const newProduct = {
    id,
    title: cleanTitle,
    tag: (tag || '').trim(),
    description: (description || '').trim(),
    price: (price || 'Consultar').trim(),
    rating: rating || '★★★★★ <span>Seleção 5 estrelas da Jany</span>',
    image: image || '',
    alt: (alt || `Foto de ${cleanTitle} — JANY BEAUTY`).trim(),
    whatsapp: (whatsapp || '').trim(),
    buyLink: (buyLink || '#checkout').trim()
  };

  // If whatsapp link wasn't provided, build a friendly default
  if (!newProduct.whatsapp) {
    const waText = encodeURIComponent(`Olá! Tenho uma dúvida sobre o produto ${cleanTitle} da JANY BEAUTY.\nOrigem: site JANY BEAUTY`);
    newProduct.whatsapp = `https://wa.me/5584987408061?text=${waText}`;
  }

  // Prepend to catalog so new items appear prominently
  products.unshift(newProduct);
  saveProducts(products);

  return res.status(201).json({
    success: true,
    product: newProduct,
    message: 'Produto cadastrado com sucesso!'
  });
});

// Protected: Update an existing product
app.put('/api/products/:id', requireAuth, (req, res) => {
  const { id } = req.params;
  const { title, tag, description, price, rating, image, alt, whatsapp, buyLink } = req.body || {};

  const products = getProducts();
  const index = products.findIndex(p => p.id === id);

  if (index === -1) {
    return res.status(404).json({
      success: false,
      error: 'Produto não encontrado.'
    });
  }

  const existing = products[index];
  const updatedTitle = title ? title.trim() : existing.title;

  const updatedProduct = {
    ...existing,
    title: updatedTitle,
    tag: tag !== undefined ? tag.trim() : existing.tag,
    description: description !== undefined ? description.trim() : existing.description,
    price: price !== undefined ? price.trim() : existing.price,
    rating: rating !== undefined ? rating : existing.rating,
    image: image !== undefined ? image : existing.image,
    alt: alt !== undefined ? alt.trim() : (existing.alt || `Foto de ${updatedTitle} — JANY BEAUTY`),
    whatsapp: whatsapp !== undefined ? whatsapp.trim() : existing.whatsapp,
    buyLink: buyLink !== undefined ? buyLink.trim() : existing.buyLink
  };

  products[index] = updatedProduct;
  saveProducts(products);

  return res.json({
    success: true,
    product: updatedProduct,
    message: 'Produto atualizado com sucesso!'
  });
});

// Protected: Delete a product
app.delete('/api/products/:id', requireAuth, (req, res) => {
  const { id } = req.params;
  const products = getProducts();
  const initialLength = products.length;
  const filtered = products.filter(p => p.id !== id);

  if (filtered.length === initialLength) {
    return res.status(404).json({
      success: false,
      error: 'Produto não encontrado para remoção.'
    });
  }

  saveProducts(filtered);
  return res.json({
    success: true,
    message: 'Produto removido com sucesso!'
  });
});

// Protected: Reset catalog to defaults
app.post('/api/products/reset', requireAuth, (req, res) => {
  try {
    if (fs.existsSync(DEFAULT_PRODUCTS_FILE)) {
      const defaults = JSON.parse(fs.readFileSync(DEFAULT_PRODUCTS_FILE, 'utf-8'));
      saveProducts(defaults);
      return res.json({
        success: true,
        products: defaults,
        message: 'Catálogo restaurado para a seleção padrão original!'
      });
    }
  } catch (err) {
    console.error('Erro ao restaurar catálogo padrão:', err);
  }
  return res.status(500).json({
    success: false,
    error: 'Não foi possível restaurar os produtos padrão.'
  });
});

// ----------------- STATIC FILES & PAGES ----------------- //

app.use(express.static(__dirname, {
  maxAge: '0',
  setHeaders: (res, filePath) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    if (filePath.endsWith('.webmanifest')) {
      res.setHeader('Content-Type', 'application/manifest+json');
    } else if (filePath.endsWith('.webp')) {
      res.setHeader('Content-Type', 'image/webp');
    } else if (filePath.endsWith('.png')) {
      res.setHeader('Content-Type', 'image/png');
    } else if (filePath.endsWith('.jpg') || filePath.endsWith('.jpeg')) {
      res.setHeader('Content-Type', 'image/jpeg');
    }
  }
}));

// Serve Admin Panel
app.get(['/admin', '/admin.html'], (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

// Fallback to Main Store
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Initialize and verify Firebase connectivity on startup
testConnection().then(ok => {
  if (ok) {
    console.log('🔥 Firebase Firestore integrado e operacional!');
  }
}).catch(err => {
  console.warn('Verificação inicial do Firebase:', err ? err.message : '');
});

app.listen(PORT, HOST, () => {
  console.log(`JANY BEAUTY server running on http://${HOST}:${PORT}`);
  console.log(`Admin panel accessible at http://${HOST}:${PORT}/admin`);
});

