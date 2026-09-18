import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pg from 'pg';
import crypto from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const {Pool}=pg;
const app=express();
const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.DATABASE_SSL==='true'?{rejectUnauthorized:false}:false});
const __dirname=path.dirname(fileURLToPath(import.meta.url));
const publicDir=path.join(__dirname,"public");

async function initDatabase(){
  const fs = await import('node:fs/promises');
  const schemaPath = path.join(__dirname,'schema.sql');
  const schema = await fs.readFile(schemaPath,'utf8');
  await pool.query(schema);
  if(process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD){
    const email=String(process.env.ADMIN_EMAIL).trim().toLowerCase();
    const hash=await bcrypt.hash(String(process.env.ADMIN_PASSWORD),12);
    await pool.query('INSERT INTO admins(email,password_hash) VALUES($1,$2) ON CONFLICT(email) DO UPDATE SET password_hash=EXCLUDED.password_hash',[email,hash]);
    console.log('Admin user initialized:', email);
  }
  console.log('Database schema initialized successfully.');
}
const allowedStatuses=new Set(['NEW','ACCEPTED','PREPARING','READY','OUT_FOR_DELIVERY','DELIVERED','CANCELLED']);
app.disable('x-powered-by');
app.use(helmet({contentSecurityPolicy:false}));
app.use(cors({origin:process.env.CORS_ORIGIN?.split(',').map(x=>x.trim())||false}));
app.use(express.json({limit:'1mb',verify:(req,res,buf)=>{if(req.originalUrl==='/api/payments/razorpay/webhook')req.rawBody=Buffer.from(buf)}}));
app.use('/api/auth',rateLimit({windowMs:15*60*1000,max:20,standardHeaders:true,legacyHeaders:false}));
app.use('/api/otp',rateLimit({windowMs:15*60*1000,max:8,standardHeaders:true,legacyHeaders:false}));
app.use('/api/orders',rateLimit({windowMs:60*1000,max:60,standardHeaders:true,legacyHeaders:false}));
app.use(express.static(publicDir));
const q=(text,params=[])=>pool.query(text,params);
function auth(req,res,next){try{const h=req.headers.authorization||'';if(!h.startsWith('Bearer '))return res.status(401).json({error:'Unauthorized'});req.admin=jwt.verify(h.slice(7),process.env.JWT_SECRET);next()}catch{return res.status(401).json({error:'Unauthorized'})}}
function cleanPhone(v){return String(v||'').replace(/[^0-9+]/g,'').slice(0,20)}
function tokenHash(v){return crypto.createHash('sha256').update(String(v||'')).digest('hex')}
function razorConfigured(){return !!(process.env.RAZORPAY_KEY_ID&&process.env.RAZORPAY_KEY_SECRET)}
function timingSafeEqualHex(a,b){try{const aa=Buffer.from(a,'hex'),bb=Buffer.from(b,'hex');return aa.length===bb.length&&crypto.timingSafeEqual(aa,bb)}catch{return false}}
async function notify(event,payload){const url=process.env.NOTIFICATION_WEBHOOK_URL;if(!url)return;try{await fetch(url,{method:'POST',headers:{'content-type':'application/json',...(process.env.NOTIFICATION_WEBHOOK_SECRET?{'x-webhook-secret':process.env.NOTIFICATION_WEBHOOK_SECRET}:{})},body:JSON.stringify({event,payload})})}catch(e){console.warn('Notification webhook failed',e.message)}}
function otpRequired(){return process.env.OTP_REQUIRED==='true'}
function bearer(req){const h=req.headers.authorization||'';return h.startsWith('Bearer ')?h.slice(7):''}
app.get('/api/health',async(_,res)=>{try{await q('SELECT 1');res.json({ok:true})}catch{res.status(503).json({ok:false})}});
app.post('/api/auth/login',async(req,res)=>{const email=String(req.body.email||'').trim().toLowerCase(),password=String(req.body.password||'');if(!email||!password)return res.status(400).json({error:'Email and password are required'});const r=await q('SELECT * FROM admins WHERE email=$1',[email]);if(!r.rowCount||!(await bcrypt.compare(password,r.rows[0].password_hash)))return res.status(401).json({error:'Invalid credentials'});const token=jwt.sign({sub:r.rows[0].id,email},process.env.JWT_SECRET,{expiresIn:'12h'});res.json({token})});
app.get('/api/settings',async(_,res)=>{const r=await q('SELECT data FROM settings WHERE id=1');res.json(r.rows[0]?.data||{})});
app.put('/api/settings',auth,async(req,res)=>{const data=req.body||{};await q('UPDATE settings SET data=$1,updated_at=now() WHERE id=1',[JSON.stringify(data)]);res.json(data)});
app.get('/api/products',async(_,res)=>{const r=await q('SELECT id,name,en,price,description AS desc,image,video,published FROM products WHERE published=true ORDER BY created_at DESC');res.json(r.rows)});
app.get('/api/admin/products',auth,async(_,res)=>{const r=await q('SELECT id,name,en,price,description AS desc,image,video,published FROM products ORDER BY created_at DESC');res.json(r.rows)});
app.post('/api/admin/products',auth,async(req,res)=>{const x=req.body||{};if(!String(x.name||'').trim())return res.status(400).json({error:'Name required'});const r=await q('INSERT INTO products(name,en,price,description,image,video,published) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id,name,en,price,description AS desc,image,video,published',[String(x.name).trim(),String(x.en||''),Number(x.price||0),String(x.desc||''),String(x.image||''),String(x.video||''),x.published!==false]);res.status(201).json(r.rows[0])});
app.put('/api/admin/products/:id',auth,async(req,res)=>{const x=req.body||{};const r=await q('UPDATE products SET name=$1,en=$2,price=$3,description=$4,image=$5,video=$6,published=$7,updated_at=now() WHERE id=$8 RETURNING id,name,en,price,description AS desc,image,video,published',[String(x.name||'').trim(),String(x.en||''),Number(x.price||0),String(x.desc||''),String(x.image||''),String(x.video||''),x.published!==false,req.params.id]);if(!r.rowCount)return res.status(404).json({error:'Not found'});res.json(r.rows[0])});
app.delete('/api/admin/products/:id',auth,async(req,res)=>{await q('DELETE FROM products WHERE id=$1',[req.params.id]);res.status(204).end()});
app.post('/api/otp/request',async(req,res)=>{
 const phone=cleanPhone(req.body.phone); if(!phone)return res.status(400).json({error:'Valid mobile number required'});
 if(!process.env.OTP_WEBHOOK_URL)return res.status(503).json({error:'OTP service is not configured'});
 const code=String(crypto.randomInt(100000,1000000)); const hash=tokenHash(code+'|'+process.env.OTP_SECRET);
 await q('UPDATE customer_otps SET used=true WHERE phone=$1 AND used=false',[phone]);
 await q("INSERT INTO customer_otps(phone,code_hash,expires_at) VALUES($1,$2,now()+interval '5 minutes')",[phone,hash]);
 await fetch(process.env.OTP_WEBHOOK_URL,{method:'POST',headers:{'content-type':'application/json',...(process.env.OTP_WEBHOOK_SECRET?{'x-webhook-secret':process.env.OTP_WEBHOOK_SECRET}:{})},body:JSON.stringify({phone,otp:code,channel:'sms'})});
 res.json({ok:true,expiresIn:300});
});
app.post('/api/otp/verify',async(req,res)=>{
 const phone=cleanPhone(req.body.phone),code=String(req.body.code||''); if(!phone||!/^\d{6}$/.test(code))return res.status(400).json({error:'Mobile and 6 digit OTP are required'});
 const r=await q("SELECT * FROM customer_otps WHERE phone=$1 AND used=false AND attempts<5 AND expires_at>now() ORDER BY created_at DESC LIMIT 1",[phone]); if(!r.rowCount)return res.status(400).json({error:'OTP expired, locked, or not found'});
 const ok=tokenHash(code+'|'+process.env.OTP_SECRET)===r.rows[0].code_hash; if(!ok){await q('UPDATE customer_otps SET attempts=attempts+1 WHERE id=$1',[r.rows[0].id]);return res.status(400).json({error:'Invalid OTP'});}
 await q('UPDATE customer_otps SET used=true WHERE id=$1',[r.rows[0].id]); const token=jwt.sign({phone,scope:'phone_verified'},process.env.JWT_SECRET,{expiresIn:'30m'}); res.json({ok:true,verificationToken:token});
});
app.post('/api/orders',async(req,res)=>{const x=req.body||{},name=String(x.name||'').trim().slice(0,120),phone=cleanPhone(x.phone),address=String(x.address||'').trim().slice(0,500),items=Array.isArray(x.items)?x.items:[];if(!name||!phone||!address||!items.length)return res.status(400).json({error:'Name, mobile, address and items are required'});if(otpRequired()){try{const v=jwt.verify(String(x.verificationToken||''),process.env.JWT_SECRET);if(v.scope!=='phone_verified'||cleanPhone(v.phone)!==phone)throw Error()}catch{return res.status(401).json({error:'Phone verification required'})}}const ids=items.map(i=>i.productId).filter(Boolean);const r=await q('SELECT id,name,price FROM products WHERE id=ANY($1::uuid[]) AND published=true',[ids]);const byId=new Map(r.rows.map(p=>[p.id,p]));let normalized=[],subtotal=0;for(const item of items){const p=byId.get(item.productId);const qty=Math.max(1,Math.min(99,Number(item.qty)||1));if(!p)return res.status(400).json({error:'One or more menu items are unavailable'});const price=Number(p.price);normalized.push({productId:p.id,name:p.name,qty,price});subtotal+=price*qty}const settings=(await q('SELECT data FROM settings WHERE id=1')).rows[0]?.data||{};const fee=Math.max(0,Number(settings.deliveryFee)||0),total=subtotal+fee,id='SK'+crypto.randomBytes(4).toString('hex').toUpperCase();const accessToken=crypto.randomBytes(24).toString('hex');const paymentMethod=String(x.paymentMethod||'COD').toUpperCase()==='ONLINE'?'ONLINE':'COD';const ins=await q('INSERT INTO orders(id,customer_name,phone,address,items,subtotal,delivery_fee,total,payment_method,payment_status,access_token_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id,customer_name AS name,phone,address,items,subtotal,delivery_fee,total,status,payment_method AS "paymentMethod",payment_status AS "paymentStatus",created_at AS "createdAt"',[id,name,phone,address,JSON.stringify(normalized),subtotal,fee,total,paymentMethod,paymentMethod==='COD'?'PENDING':'PENDING',tokenHash(accessToken)]);notify('order.created',{id,name,phone,total,paymentMethod});res.status(201).json({...ins.rows[0],accessToken})});
app.get('/api/orders',async(req,res)=>{const phone=cleanPhone(req.query.phone);if(!phone)return res.status(400).json({error:'phone required'});const r=await q('SELECT id,customer_name AS name,phone,address,items,subtotal,delivery_fee,total,status,payment_method AS "paymentMethod",payment_status AS "paymentStatus",created_at AS "createdAt",completed_at AS "completedAt" FROM orders WHERE phone=$1 ORDER BY created_at DESC LIMIT 100',[phone]);res.json(r.rows)});
app.get('/api/admin/orders',auth,async(_,res)=>{const r=await q('SELECT id,customer_name AS name,phone,address,items,subtotal,delivery_fee,total,status,payment_method AS "paymentMethod",payment_status AS "paymentStatus",created_at AS "createdAt",updated_at AS "updatedAt",completed_at AS "completedAt" FROM orders ORDER BY created_at DESC LIMIT 1000');res.json(r.rows)});
app.patch('/api/admin/orders/:id/status',auth,async(req,res)=>{const status=String(req.body.status||'').toUpperCase();if(!allowedStatuses.has(status))return res.status(400).json({error:'Invalid status'});const r=await q('UPDATE orders SET status=$1,updated_at=now(),completed_at=CASE WHEN $1=\'DELIVERED\' THEN COALESCE(completed_at,now()) ELSE completed_at END WHERE id=$2 RETURNING id,status,updated_at AS "updatedAt",completed_at AS "completedAt"',[status,req.params.id]);if(!r.rowCount)return res.status(404).json({error:'Order not found'});res.json(r.rows[0])});
app.post('/api/admin/orders/:id/delivery-session',auth,async(req,res)=>{const order=await q('SELECT id FROM orders WHERE id=$1',[req.params.id]);if(!order.rowCount)return res.status(404).json({error:'Order not found'});await q('UPDATE delivery_sessions SET active=false WHERE order_id=$1',[req.params.id]);const token=crypto.randomBytes(24).toString('hex');const r=await q('INSERT INTO delivery_sessions(order_id,token_hash) VALUES($1,$2) RETURNING id,expires_at AS "expiresAt"',[req.params.id,tokenHash(token)]);res.status(201).json({orderId:req.params.id,token,expiresAt:r.rows[0].expiresAt,deliveryUrl:'/delivery.html?token='+token})});
app.get('/api/admin/delivery-sessions/:orderId',auth,async(req,res)=>{
 const r=await q("SELECT id,active,created_at AS \"createdAt\",expires_at AS \"expiresAt\" FROM delivery_sessions WHERE order_id=$1 ORDER BY created_at DESC LIMIT 10",[req.params.orderId]);
 res.json(r.rows);
});
app.post('/api/delivery/location',async(req,res)=>{const token=bearer(req);if(!token)return res.status(401).json({error:'Delivery token required'});const s=await q('SELECT order_id FROM delivery_sessions WHERE token_hash=$1 AND active=true AND expires_at>now()',[tokenHash(token)]);if(!s.rowCount)return res.status(401).json({error:'Invalid or expired delivery token'});const lat=Number(req.body.latitude),lng=Number(req.body.longitude),accuracy=req.body.accuracy==null?null:Number(req.body.accuracy);if(!Number.isFinite(lat)||!Number.isFinite(lng)||lat<-90||lat>90||lng<-180||lng>180)return res.status(400).json({error:'Invalid coordinates'});await q('INSERT INTO tracking_points(order_id,latitude,longitude,accuracy) VALUES($1,$2,$3,$4)',[s.rows[0].order_id,lat,lng,Number.isFinite(accuracy)?accuracy:null]);await q("UPDATE orders SET status=CASE WHEN status IN ('READY','OUT_FOR_DELIVERY') THEN 'OUT_FOR_DELIVERY' ELSE status END,updated_at=now() WHERE id=$1",[s.rows[0].order_id]);res.json({ok:true,orderId:s.rows[0].order_id});});
app.get('/api/orders/:id/tracking',async(req,res)=>{const token=String(req.query.accessToken||'');if(!token)return res.status(401).json({error:'Access token required'});const o=await q('SELECT id,status,address,updated_at AS "updatedAt" FROM orders WHERE id=$1 AND access_token_hash=$2',[req.params.id,tokenHash(token)]);if(!o.rowCount)return res.status(404).json({error:'Order not found'});const t=await q('SELECT latitude,longitude,accuracy,recorded_at AS "recordedAt" FROM tracking_points WHERE order_id=$1 ORDER BY recorded_at DESC LIMIT 1',[req.params.id]);res.json({order:o.rows[0],location:t.rows[0]||null});});
app.post('/api/payments/razorpay/order',async(req,res)=>{
  if(!razorConfigured())return res.status(503).json({error:'Online payment is not configured on this server'});
  const orderId=String(req.body.orderId||''),accessToken=String(req.body.accessToken||'');
  const r=await q('SELECT id,total,payment_method AS \"paymentMethod\",payment_status AS \"paymentStatus\",customer_name AS name,phone FROM orders WHERE id=$1 AND access_token_hash=$2',[orderId,tokenHash(accessToken)]);
  if(!r.rowCount)return res.status(404).json({error:'Order not found'});
  const o=r.rows[0]; if(o.paymentMethod!=='ONLINE')return res.status(400).json({error:'This order is not an online-payment order'});
  const amount=Math.round(Number(o.total)*100);
  const auth=Buffer.from(process.env.RAZORPAY_KEY_ID+':'+process.env.RAZORPAY_KEY_SECRET).toString('base64');
  const rr=await fetch('https://api.razorpay.com/v1/orders',{method:'POST',headers:{Authorization:'Basic '+auth,'Content-Type':'application/json'},body:JSON.stringify({amount,currency:'INR',receipt:o.id,notes:{sarkar_order_id:o.id}})});
  const data=await rr.json(); if(!rr.ok)return res.status(502).json({error:data?.error?.description||'Payment provider error'});
  await q('INSERT INTO payments(order_id,provider,provider_order_id,amount,currency,status) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(provider_order_id) DO UPDATE SET amount=EXCLUDED.amount,status=EXCLUDED.status',[o.id,'razorpay',data.id,amount,'INR','CREATED']);
  res.json({keyId:process.env.RAZORPAY_KEY_ID,orderId:o.id,razorpayOrderId:data.id,amount,currency:'INR',name:o.name,phone:o.phone});
});
app.post('/api/payments/razorpay/verify',async(req,res)=>{
  const orderId=String(req.body.orderId||''),accessToken=String(req.body.accessToken||''),paymentId=String(req.body.razorpay_payment_id||''),razorpayOrderId=String(req.body.razorpay_order_id||''),signature=String(req.body.razorpay_signature||'');
  const r=await q('SELECT id FROM orders WHERE id=$1 AND access_token_hash=$2',[orderId,tokenHash(accessToken)]); if(!r.rowCount)return res.status(404).json({error:'Order not found'});
  const p=await q('SELECT * FROM payments WHERE order_id=$1 AND provider=\'razorpay\' AND provider_order_id=$2',[orderId,razorpayOrderId]); if(!p.rowCount)return res.status(400).json({error:'Payment order mismatch'});
  const expected=crypto.createHmac('sha256',process.env.RAZORPAY_KEY_SECRET||'').update(razorpayOrderId+'|'+paymentId).digest('hex');
  if(!timingSafeEqualHex(expected,signature))return res.status(400).json({error:'Invalid payment signature'});
  await q('UPDATE payments SET provider_payment_id=$1,signature=$2,status=$3,updated_at=now() WHERE id=$4',[paymentId,signature,'CAPTURED',p.rows[0].id]);
  await q('UPDATE orders SET payment_status=\'PAID\',updated_at=now() WHERE id=$1',[orderId]);
  notify('payment.captured',{orderId,paymentId,provider:'razorpay'});
  res.json({ok:true,paymentStatus:'PAID'});
});
app.post('/api/payments/razorpay/webhook',async(req,res)=>{
  const secret=process.env.RAZORPAY_WEBHOOK_SECRET;
  if(!secret)return res.status(503).json({error:'Webhook secret is not configured'});
  const signature=String(req.headers['x-razorpay-signature']||'');
  const raw=req.rawBody||Buffer.from('');
  const expected=crypto.createHmac('sha256',secret).update(raw).digest('hex');
  if(!timingSafeEqualHex(expected,signature))return res.status(401).json({error:'Invalid webhook signature'});
  const event=String(req.body?.event||'');
  const p=req.body?.payload?.payment?.entity||{};
  const providerPaymentId=String(p.id||'');
  const providerOrderId=String(p.order_id||'');
  if(providerOrderId){
    let status=null;
    if(event==='payment.captured'||event==='order.paid')status='PAID';
    else if(event==='payment.failed')status='FAILED';
    else if(event==='refund.created')status='REFUNDED';
    if(status){
      await q('UPDATE payments SET provider_payment_id=COALESCE($1,provider_payment_id),status=$2,signature=$3,updated_at=now() WHERE provider_order_id=$4',[providerPaymentId,status,signature,providerOrderId]);
      await q('UPDATE orders SET payment_status=$1,updated_at=now() WHERE id=(SELECT order_id FROM payments WHERE provider_order_id=$2)',[status,providerOrderId]);
    }
  }
  res.json({ok:true});
});
app.post('/api/notifications/order-status',auth,async(req,res)=>{const id=String(req.body.orderId||''),status=String(req.body.status||'').toUpperCase();if(!id||!allowedStatuses.has(status))return res.status(400).json({error:'orderId and valid status required'});const r=await q('SELECT id,customer_name AS name,phone,total FROM orders WHERE id=$1',[id]);if(!r.rowCount)return res.status(404).json({error:'Order not found'});await notify('order.status',{...r.rows[0],status});res.json({ok:true})});
app.get('/api/admin/daily',auth,async(_,res)=>{const r=await q(`SELECT DATE(completed_at) AS day,COUNT(*)::int AS orders,COUNT(DISTINCT phone)::int AS customers,COALESCE(SUM(total),0)::numeric AS total FROM orders WHERE status='DELIVERED' AND completed_at IS NOT NULL GROUP BY DATE(completed_at) ORDER BY day DESC LIMIT 366`);res.json(r.rows)});
app.get('/',(req,res)=>res.sendFile(path.join(publicDir,'sarkar_restaurant_CUSTOMER_v11.html')));
app.use((req,res)=>{if(req.path.startsWith('/api/'))return res.status(404).json({error:'Not found'});res.status(404).send('Not found')});
const port=Number(process.env.PORT||3000);

async function startServer(){
  try{
    await initDatabase();
    app.listen(port,()=>console.log(`Sarkar production server listening on :${port}`));
  }catch(error){
    console.error('Database initialization failed:',error);
    process.exit(1);
  }
}
startServer();
