import 'dotenv/config';
import bcrypt from 'bcryptjs';
import pg from 'pg';
const {Pool}=pg;
if(!process.env.DATABASE_URL||!process.env.ADMIN_EMAIL||!process.env.ADMIN_PASSWORD) throw new Error('Set DATABASE_URL, ADMIN_EMAIL and ADMIN_PASSWORD in .env');
const pool=new Pool({connectionString:process.env.DATABASE_URL});
const hash=await bcrypt.hash(process.env.ADMIN_PASSWORD,12);
await pool.query('INSERT INTO admins(email,password_hash) VALUES($1,$2) ON CONFLICT(email) DO UPDATE SET password_hash=EXCLUDED.password_hash',[process.env.ADMIN_EMAIL.toLowerCase(),hash]);
await pool.end(); console.log('Admin user ready:',process.env.ADMIN_EMAIL);
