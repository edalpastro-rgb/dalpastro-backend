import 'dotenv/config'; import express from 'express'; import cors from 'cors'; import helmet from 'helmet'; import jwt from 'jsonwebtoken'; import bcrypt from 'bcryptjs'; import pkg from 'pg'; const { Pool } = pkg;

const app = express(); app.use(helmet()); app.use(cors()); app.use(express.json({ limit: '10mb' }));

const PORT = process.env.PORT || 3000; const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret'; const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.PGSSL === 'disable' ? false : { rejectUnauthorized: false } });

async function init() { await pool.query(


    create table if not exists users(       id serial primary key,       email text unique not null,       password_hash text not null,       created_at timestamptz default now()     );     create table if not exists areas(       id serial primary key,       name text not null,       is_active boolean default true     );     create table if not exists contacts(       id serial primary key,       area_id int references areas(id) on delete set null,       name text not null,       phone text,       email text,       groups text[] default '{}',       photo_url text,       address text,       lat double precision,       lon double precision,       created_at timestamptz default now()     );     create table if not exists events(       id serial primary key,       contact_id int references contacts(id) on delete cascade,       area_id int references areas(id) on delete set null,       title text,       start_at timestamptz,       end_at timestamptz,       status text check (status in ('verde','giallo','rosso')) default 'rosso',       notes text,       created_at timestamptz default now()     );     create table if not exists notes(       id serial primary key,       contact_id int references contacts(id) on delete cascade,       type text check (type in ('text','audio','photo')) not null,       text text,       media_url text,       transcript text,       created_at timestamptz default now()     );  
); const { rows } = await pool.query(select count(*)::int as c from areas); if (rows[0].c === 0) { await pool.query(insert into areas(name) values ($1),($2), ['Optima Italia', 'N 21']); } } init().catch(console.error);

function auth(req, res, next) { const h = req.headers.authorization || ''; const token = h.startsWith('Bearer ') ? h.slice(7) : null; if (!token) return res.status(401).json({ error: 'no_token' }); try { req.user = jwt.verify(token, JWT_SECRET); next(); } catch { res.status(401).json({ error: 'invalid_token' }); } }

app.get('/health', (_req, res) => res.json({ ok: true }));

app.post('/auth/signup', async (req, res) => { const { email, password } = req.body || {}; if (!email || !password) return res.status(400).json({ error: 'missing_fields' }); const hash = await bcrypt.hash(password, 10); try { const { rows } = await pool.query( insert into users(email, password_hash) values ($1,$2) returning id,email, [email, hash] ); const user = rows[0]; const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' }); res.json({ token, user }); } catch (e) { if (e.code === '23505') return res.status(409).json({ error: 'email_exists' }); res.status(500).json({ error: 'signup_failed' }); } });

app.post('/auth/login', async (req, res) => { const { email, password } = req.body || {}; const { rows } = await pool.query(select * from users where email=$1, [email]); const user = rows[0]; if (!user) return res.status(401).json({ error: 'invalid_credentials' }); const ok = await bcrypt.compare(password, user.password_hash); if (!ok) return res.status(401).json({ error: 'invalid_credentials' }); const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' }); res.json({ token, user: { id: user.id, email: user.email } }); });

app.get('/areas', auth, async (_req, res) => { const { rows } = await pool.query(select * from areas order by id); res.json(rows); });

app.put('/areas/:id', auth, async (req, res) => { const { name, is_active } = req.body || {}; await pool.query( update areas set name=coalesce($1,name), is_active=coalesce($2,is_active) where id=$3, [name, is_active, req.params.id] ); res.json({ ok: true }); });

app.listen(PORT, () => console.log(API on :${PORT}));
