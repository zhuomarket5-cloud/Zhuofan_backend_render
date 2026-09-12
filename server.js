import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import { Pool } from 'pg';
import { randomUUID } from 'crypto';
import fs from 'fs/promises';

const app=express();
const PORT=Number(process.env.PORT||10000);
const JWT_SECRET=process.env.JWT_SECRET||'dev-only-change-me';
const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.DATABASE_URL?.includes('localhost')?false:{rejectUnauthorized:false}});
const q=(text,params=[])=>pool.query(text,params);
const uid=()=>randomUUID();
const clean=v=>v==null?'':String(v).trim();
const roleAdmin=r=>['admin','owner'].includes(r);

app.use(cors({origin:true,credentials:true,methods:['GET','POST','PUT','PATCH','DELETE','OPTIONS'],allowedHeaders:['Content-Type','Authorization']}));
app.use(express.json({limit:'10mb'}));
app.use(express.urlencoded({extended:true,limit:'10mb'}));
app.use((req,res,next)=>{res.setHeader('Cache-Control','no-store');next()});

function signUser(u){return jwt.sign({id:u.id,email:u.email,role:u.role},JWT_SECRET,{expiresIn:'30d'});}
function auth(req,res,next){try{const h=req.headers.authorization||'';if(!h.startsWith('Bearer '))throw new Error();req.user=jwt.verify(h.slice(7),JWT_SECRET);next()}catch{res.status(401).json({error:'Authentication required'})}}
function admin(req,res,next){auth(req,res,()=>roleAdmin(req.user.role)?next():res.status(403).json({error:'Admin only'}))}
function sendError(res,e,status=500){console.error(e);res.status(status).json({error:e?.message||'Server error'});}
const upload=multer({storage:multer.memoryStorage(),limits:{fileSize:5*1024*1024}});

async function init(){
 await q(await fs.readFile(new URL('./schema.sql',import.meta.url),'utf8'));
 // Safe compatibility columns for databases created by the previous backend.
 await q("ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar text");
 await q("ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now()");
 await q("ALTER TABLE promotions ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now()");
 await q("ALTER TABLE push_subscriptions ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now()").catch(()=>{});
 if(process.env.OWNER_EMAIL&&process.env.OWNER_PASSWORD){
  const email=clean(process.env.OWNER_EMAIL).toLowerCase();
  const r=await q('SELECT id,role FROM users WHERE lower(email)=lower($1)',[email]);
  if(!r.rowCount){const u={id:uid(),email,password_hash:await bcrypt.hash(process.env.OWNER_PASSWORD,12),name:'ZhuoMarket Owner',role:'owner'};await q('INSERT INTO users(id,email,password_hash,name,role) VALUES($1,$2,$3,$4,$5)',[u.id,u.email,u.password_hash,u.name,u.role]);}
  else if(r.rows[0].role!=='owner') await q("UPDATE users SET role='owner',updated_at=now() WHERE id=$1",[r.rows[0].id]);
 }
}

app.get('/api/health',async(req,res)=>{try{await q('SELECT 1');res.json({ok:true,service:'zhuo-market-backend',version:'2.0.0',database:'connected'})}catch(e){sendError(res,e,503)}});
app.get('/api/products',async(req,res)=>{try{const r=await q('SELECT * FROM products WHERE active=true ORDER BY created_at DESC');res.json({products:r.rows,data:r.rows})}catch(e){sendError(res,e)}});
app.get('/api/brands',async(req,res)=>{try{const r=await q("SELECT DISTINCT brand FROM products WHERE active=true AND brand<>'' ORDER BY brand");const brands=r.rows.map(x=>x.brand);res.json({brands,data:brands})}catch(e){sendError(res,e)}});
app.get('/api/promotions',async(req,res)=>{try{const r=await q('SELECT * FROM promotions WHERE active=true ORDER BY created_at DESC');res.json({promotions:r.rows,data:r.rows})}catch(e){sendError(res,e)}});

app.post('/api/auth/register',async(req,res)=>{try{const email=clean(req.body.email||req.body.gmail).toLowerCase(),password=String(req.body.password||'');if(!email||!password)return res.status(400).json({error:'Email and password required'});if(password.length<6)return res.status(400).json({error:'Password must be at least 6 characters'});if(req.body.confirmPassword!=null&&password!==String(req.body.confirmPassword))return res.status(400).json({error:'Passwords do not match'});const ex=await q('SELECT id FROM users WHERE lower(email)=lower($1)',[email]);if(ex.rowCount)return res.status(409).json({error:'Email already registered'});const u={id:uid(),email,password_hash:await bcrypt.hash(password,12),name:clean(req.body.name)||email.split('@')[0],role:'client'};await q('INSERT INTO users(id,email,password_hash,name,role) VALUES($1,$2,$3,$4,$5)',[u.id,u.email,u.password_hash,u.name,u.role]);res.status(201).json({token:signUser(u),user:{id:u.id,email:u.email,name:u.name,role:u.role,avatar:null}})}catch(e){sendError(res,e)}});
app.post('/api/auth/login',async(req,res)=>{try{const email=clean(req.body.email||req.body.gmail).toLowerCase(),password=String(req.body.password||'');const r=await q('SELECT * FROM users WHERE lower(email)=lower($1)',[email]);if(!r.rowCount||!(await bcrypt.compare(password,r.rows[0].password_hash)))return res.status(401).json({error:'Invalid email or password'});const u=r.rows[0];res.json({token:signUser(u),user:{id:u.id,email:u.email,name:u.name,role:u.role,avatar:u.avatar||null}})}catch(e){sendError(res,e)}});
app.get('/api/auth/me',auth,async(req,res)=>{try{const r=await q('SELECT id,email,name,role,avatar,created_at FROM users WHERE id=$1',[req.user.id]);if(!r.rowCount)return res.status(404).json({error:'User not found'});res.json({user:r.rows[0]})}catch(e){sendError(res,e)}});
app.patch('/api/auth/me',auth,async(req,res)=>{try{const name=req.body.name==null?null:clean(req.body.name);const avatar=req.body.avatar==null?null:clean(req.body.avatar);const r=await q('UPDATE users SET name=COALESCE($2,name),avatar=COALESCE($3,avatar),updated_at=now() WHERE id=$1 RETURNING id,email,name,role,avatar,created_at',[req.user.id,name,avatar]);res.json({user:r.rows[0]})}catch(e){sendError(res,e)}});
app.post('/api/auth/logout',auth,(req,res)=>res.json({ok:true}));
app.post('/api/auth/refresh',auth,async(req,res)=>{const r=await q('SELECT id,email,role FROM users WHERE id=$1',[req.user.id]);if(!r.rowCount)return res.status(404).json({error:'User not found'});res.json({token:signUser(r.rows[0])})});

app.get('/api/payment-methods',async(req,res)=>{try{const r=await q('SELECT id,provider,description,instructions,transfer_number AS "transferNumber",account_number AS "accountNumber",active FROM payment_methods WHERE active=true ORDER BY created_at');res.json({paymentMethods:r.rows,data:r.rows})}catch(e){sendError(res,e)}});
app.get('/api/admin/payment-methods',admin,async(req,res)=>{try{const r=await q('SELECT id,provider,description,instructions,transfer_number AS "transferNumber",account_number AS "accountNumber",active FROM payment_methods ORDER BY created_at');res.json({paymentMethods:r.rows,data:r.rows})}catch(e){sendError(res,e)}});
app.post('/api/admin/payment-methods',admin,async(req,res)=>{try{const b=req.body,r=await q('INSERT INTO payment_methods(id,provider,description,instructions,transfer_number,account_number,active) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *',[uid(),clean(b.provider)||'Manual',clean(b.description),clean(b.instructions),clean(b.transferNumber||b.transfer_number),clean(b.accountNumber||b.account_number),b.active!==false]);res.status(201).json({paymentMethod:r.rows[0]})}catch(e){sendError(res,e,400)}});
app.patch('/api/admin/payment-methods/:id',admin,async(req,res)=>{try{const b=req.body,r=await q('UPDATE payment_methods SET provider=COALESCE($2,provider),description=COALESCE($3,description),instructions=COALESCE($4,instructions),transfer_number=COALESCE($5,transfer_number),account_number=COALESCE($6,account_number),active=COALESCE($7,active),updated_at=now() WHERE id=$1 RETURNING *',[req.params.id,b.provider,b.description,b.instructions,b.transferNumber??b.transfer_number,b.accountNumber??b.account_number,b.active]);if(!r.rowCount)return res.status(404).json({error:'Payment method not found'});res.json({paymentMethod:r.rows[0]})}catch(e){sendError(res,e,400)}});
app.delete('/api/admin/payment-methods/:id',admin,async(req,res)=>{try{const r=await q('DELETE FROM payment_methods WHERE id=$1',[req.params.id]);if(!r.rowCount)return res.status(404).json({error:'Payment method not found'});res.json({ok:true})}catch(e){sendError(res,e)}});

function normalizeItems(items){if(!Array.isArray(items)||!items.length)throw new Error('Cart is empty');return items.map(x=>({productId:x.productId||x.id,quantity:Math.max(1,parseInt(x.quantity||1,10)),name:x.name||'',brand:x.brand||'',image:x.image||''}));}
async function priceCart(items,client=q){const ids=[...new Set(items.map(x=>x.productId).filter(Boolean))];if(!ids.length)throw new Error('No products selected');const r=await client('SELECT * FROM products WHERE id=ANY($1::uuid[]) AND active=true',[ids]);const map=new Map(r.rows.map(p=>[String(p.id),p]));if(r.rowCount!==ids.length)throw new Error('One or more products are unavailable');let total=0,currency=r.rows[0]?.currency||'USD';const out=items.map(x=>{const p=map.get(String(x.productId));if(!p||Number(p.stock)<x.quantity)throw new Error(`Insufficient stock for ${p?.name||x.productId}`);total+=Number(p.price)*x.quantity;return {...x,name:p.name,brand:p.brand,unitPrice:Number(p.price),currency:p.currency,image:p.image||x.image,storage:p.storage||''}});return {out,total,currency};}
app.post('/api/orders',auth,async(req,res)=>{const c=await pool.connect();try{const raw=normalizeItems(req.body.items);const {out,total,currency}=await priceCart(raw,c.query.bind(c));await c.query('BEGIN');const oid=uid();await c.query('INSERT INTO orders(id,customer_id,items,total,currency,payment_method) VALUES($1,$2,$3,$4,$5,$6)',[oid,req.user.id,JSON.stringify(out),total,currency,clean(req.body.paymentMethod)||null]);await c.query('COMMIT');res.status(201).json({order:{id:oid,customerId:req.user.id,items:out,total,currency,paymentMethod:req.body.paymentMethod||null,paymentStatus:'pending',payment_status:'pending',status:'En attente'}})}catch(e){await c.query('ROLLBACK').catch(()=>{});sendError(res,e,400)}finally{c.release()}});
app.get('/api/orders',auth,async(req,res)=>{try{const all=roleAdmin(req.user.role)&&req.query.admin==='true';const r=await q(`SELECT o.*,u.email customer_email,u.name customer_name,u.avatar customer_avatar FROM orders o JOIN users u ON u.id=o.customer_id ${all?'':'WHERE o.customer_id=$1'} ORDER BY o.created_at DESC`,all?[]:[req.user.id]);res.json({orders:r.rows.map(o=>({...o,customer:{id:o.customer_id,email:o.customer_email,name:o.customer_name,avatar:o.customer_avatar}}))})}catch(e){sendError(res,e)}});
app.patch('/api/orders/:id/status',admin,async(req,res)=>{try{const allowed=['Confirmée','En préparation','Expédiée','Prête','Livrée','Terminée','Annulée','En attente'];const s=clean(req.body.status);if(!allowed.includes(s))return res.status(400).json({error:'Invalid order status'});const r=await q('UPDATE orders SET status=$2,updated_at=now() WHERE id=$1 RETURNING *',[req.params.id,s]);if(!r.rowCount)return res.status(404).json({error:'Order not found'});res.json({order:r.rows[0]})}catch(e){sendError(res,e,400)}});
app.patch('/api/orders/:id',admin,async(req,res)=>{if('paymentStatus' in req.body||'payment_status' in req.body)return res.status(403).json({error:'Payment status can only be changed through payment verification endpoints'});if('status' in req.body){req.body.status=req.body.status;return app._router.handle({...req,method:'PATCH',url:`/api/orders/${req.params.id}/status`,originalUrl:req.originalUrl},res,()=>{})}return res.status(400).json({error:'Use /status for order status'});});

async function submitManual(req,res){const ref=clean(req.body.transactionReference||req.body.reference||req.body.paymentReference);if(ref.length<3)return res.status(400).json({error:'Real transaction reference required'});const c=await pool.connect();try{await c.query('BEGIN');const o=await c.query('SELECT * FROM orders WHERE id=$1 AND customer_id=$2 FOR UPDATE',[req.body.orderId,req.user.id]);if(!o.rowCount)throw new Error('Order not found');const order=o.rows[0];if(order.payment_status==='paid')throw new Error('Order already paid');const dup=await c.query('SELECT id FROM payments WHERE lower(transaction_reference)=lower($1)',[ref]);if(dup.rowCount)throw new Error('Transaction reference already submitted');const p=await c.query('INSERT INTO payments(id,order_id,customer_id,payment_method,amount,currency,transaction_reference,status) VALUES($1,$2,$3,$4,$5,$6,$7,\'pending\') RETURNING *',[uid(),order.id,req.user.id,clean(req.body.paymentMethod||order.payment_method)||'manual',order.total,order.currency,ref]);await c.query('UPDATE orders SET payment_status=\'pending\',updated_at=now() WHERE id=$1',[order.id]);await c.query('COMMIT');res.status(201).json({payment:p.rows[0],status:'pending',message:'Payment pending verification'})}catch(e){await c.query('ROLLBACK').catch(()=>{});sendError(res,e,400)}finally{c.release()}}
app.post('/api/payments/manual',auth,submitManual);
app.post('/api/payments/manual/confirm',auth,submitManual);
app.get('/api/payments',auth,async(req,res)=>{try{const r=await q('SELECT p.*,o.status order_status FROM payments p JOIN orders o ON o.id=p.order_id WHERE p.customer_id=$1 ORDER BY p.created_at DESC',[req.user.id]);res.json({payments:r.rows,data:r.rows})}catch(e){sendError(res,e)}});
app.get('/api/payments/status/:orderId',auth,async(req,res)=>{try{const r=await q('SELECT p.*,o.payment_status order_payment_status,o.status order_status FROM payments p JOIN orders o ON o.id=p.order_id WHERE p.order_id=$1 AND p.customer_id=$2 ORDER BY p.created_at DESC LIMIT 1',[req.params.orderId,req.user.id]);if(!r.rowCount)return res.status(404).json({error:'Payment not found'});res.json({payment:r.rows[0],status:r.rows[0].status,order:{payment_status:r.rows[0].order_payment_status,status:r.rows[0].order_status}})}catch(e){sendError(res,e)}});
async function approvePayment(req,res){const c=await pool.connect();try{await c.query('BEGIN');const r=await c.query('SELECT p.*,o.items,o.status order_status FROM payments p JOIN orders o ON o.id=p.order_id WHERE p.id=$1 FOR UPDATE',[req.params.id]);if(!r.rowCount)throw new Error('Payment not found');const p=r.rows[0];if(p.status!=='pending')throw new Error(`Payment is already ${p.status}`);const items=Array.isArray(p.items)?p.items:[];for(const item of items){const n=Number(item.quantity||1);const s=await c.query('UPDATE products SET stock=stock-$2,updated_at=now() WHERE id=$1 AND active=true AND stock >= $2 RETURNING id,stock',[item.productId,n]);if(!s.rowCount)throw new Error(`Insufficient stock for product ${item.productId}`)}const pay=await c.query('UPDATE payments SET status=\'paid\',verified_at=now(),verified_by=$2 WHERE id=$1 RETURNING *',[p.id,req.user.id]);const order=await c.query("UPDATE orders SET payment_status='paid',status=CASE WHEN status='En attente' THEN 'Confirmée' ELSE status END,updated_at=now() WHERE id=$1 RETURNING *",[p.order_id]);await c.query('COMMIT');res.json({payment:pay.rows[0],order:order.rows[0],status:'paid',deliveryTriggered:false})}catch(e){await c.query('ROLLBACK').catch(()=>{});sendError(res,e,400)}finally{c.release()}}
app.get('/api/admin/payments',admin,async(req,res)=>{try{const status=['pending','paid','rejected','cancelled'].includes(req.query.status)?req.query.status:'pending';const r=await q(`SELECT p.*,o.items,o.total,o.currency,o.status order_status,u.email customer_email,u.name customer_name,u.avatar customer_avatar FROM payments p JOIN orders o ON o.id=p.order_id JOIN users u ON u.id=p.customer_id WHERE p.status=$1 ORDER BY p.created_at DESC`,[status]);res.json({payments:r.rows.map(p=>({...p,order:{id:p.order_id,items:p.items,total:p.total,currency:p.currency,status:p.order_status},customer:{id:p.customer_id,email:p.customer_email,name:p.customer_name,avatar:p.customer_avatar}}))})}catch(e){sendError(res,e)}});
app.post('/api/admin/payments/:id/approve',admin,approvePayment);
app.post('/api/admin/payments/:id/reject',admin,async(req,res)=>{const c=await pool.connect();try{await c.query('BEGIN');const r=await c.query("UPDATE payments SET status='rejected',rejection_reason=$2,verified_at=now(),verified_by=$3 WHERE id=$1 AND status='pending' RETURNING *",[req.params.id,clean(req.body.reason)||null,req.user.id]);if(!r.rowCount)throw new Error('Payment not pending');await c.query("UPDATE orders SET payment_status='rejected',updated_at=now() WHERE id=$1",[r.rows[0].order_id]);await c.query('COMMIT');res.json({payment:r.rows[0],status:'rejected'})}catch(e){await c.query('ROLLBACK').catch(()=>{});sendError(res,e,400)}finally{c.release()}});
// Compatibility for older frontend calls using /api/admin/payments/:id with an action/status body.
app.patch('/api/admin/payments/:id',admin,async(req,res)=>{if(req.body.status==='paid'||req.body.action==='approve')return approvePayment(req,res);if(req.body.status==='rejected'||req.body.action==='reject')return app._router.handle({...req,method:'POST',url:`/api/admin/payments/${req.params.id}/reject`,originalUrl:req.originalUrl},res,()=>{});return res.status(400).json({error:'Use approve or reject payment endpoint'})});

app.get('/api/admin/users',admin,async(req,res)=>{try{const r=await q('SELECT id,email,name,avatar,role,created_at FROM users ORDER BY created_at DESC');res.json({users:r.rows})}catch(e){sendError(res,e)}});
app.get('/api/users',auth,async(req,res)=>{if(!roleAdmin(req.user.role))return res.status(403).json({error:'Admin only'});const r=await q('SELECT id,email,name,avatar,role,created_at FROM users ORDER BY created_at DESC');res.json({users:r.rows,data:r.rows})});
app.patch('/api/admin/users/:id',admin,async(req,res)=>{try{const target=await q('SELECT id,role FROM users WHERE id=$1',[req.params.id]);if(!target.rowCount)return res.status(404).json({error:'User not found'});if(target.rows[0].role==='owner')return res.status(403).json({error:'Owner cannot be removed or changed'});const role=req.body.role==='admin'?'admin':'client';const r=await q('UPDATE users SET role=$2,updated_at=now() WHERE id=$1 RETURNING id,email,name,avatar,role',[req.params.id,role]);res.json({user:r.rows[0]})}catch(e){sendError(res,e,400)}});

app.get('/api/admin/stats',admin,async(req,res)=>{try{const [a,b,c,p]=await Promise.all([q("SELECT COALESCE(SUM(total),0) revenue,COUNT(*) orders FROM orders WHERE payment_status='paid'"),q('SELECT COUNT(*) users FROM users'),q('SELECT COUNT(*) products FROM products WHERE active=true'),q("SELECT COUNT(*) pending FROM payments WHERE status='pending'")]);const stats={totalSales:Number(a.rows[0].revenue),revenue:Number(a.rows[0].revenue),ordersCount:Number(a.rows[0].orders),usersCount:Number(b.rows[0].users),productsCount:Number(c.rows[0].products),pendingPayments:Number(p.rows[0].pending)};res.json({...stats,stats})}catch(e){sendError(res,e)}});

app.get('/api/user-state',auth,async(req,res)=>{try{const r=await q('SELECT cart,wishlist FROM user_state WHERE user_id=$1',[req.user.id]);res.json(r.rowCount?r.rows[0]:{cart:[],wishlist:[]})}catch(e){sendError(res,e)}});
app.put('/api/user-state',auth,async(req,res)=>{try{await q('INSERT INTO user_state(user_id,cart,wishlist) VALUES($1,$2,$3) ON CONFLICT(user_id) DO UPDATE SET cart=$2,wishlist=$3,updated_at=now()',[req.user.id,JSON.stringify(req.body.cart||[]),JSON.stringify(req.body.wishlist||[])]);res.json({ok:true})}catch(e){sendError(res,e)}});
app.get('/api/notifications',auth,async(req,res)=>{try{const r=await q('SELECT * FROM notifications WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100',[req.user.id]);res.json({notifications:r.rows})}catch(e){sendError(res,e)}});

app.post('/api/messages',auth,async(req,res)=>{try{const a=await q("SELECT id FROM users WHERE role IN ('owner','admin') ORDER BY CASE WHEN role='owner' THEN 0 ELSE 1 END,created_at LIMIT 1");if(!a.rowCount)return res.status(503).json({error:'No admin configured'});const body=clean(req.body.message||req.body.body);if(!body)return res.status(400).json({error:'Message required'});const r=await q('INSERT INTO messages(id,sender_id,receiver_id,body) VALUES($1,$2,$3,$4) RETURNING *',[uid(),req.user.id,a.rows[0].id,body]);res.status(201).json({message:r.rows[0]})}catch(e){sendError(res,e,400)}});
app.get('/api/admin/messages',admin,async(req,res)=>{try{const r=await q(`SELECT m.*,s.name sender_name,s.email sender_email,s.avatar sender_avatar FROM messages m LEFT JOIN users s ON s.id=m.sender_id WHERE m.receiver_id=$1 OR m.sender_id=$1 ORDER BY m.created_at ASC`,[req.user.id]);const groups=new Map();for(const m of r.rows){const other=String(m.sender_id)===String(req.user.id)?m.receiver_id:m.sender_id;const key=String(other||'');const g=groups.get(key)||{id:key,name:m.sender_id===req.user.id?'Admin':m.sender_name,email:m.sender_email,avatar:m.sender_avatar,lastMessage:'',lastMessageAt:m.created_at,unread:0};g.lastMessage=m.body;g.lastMessageAt=m.created_at;if(m.receiver_id===req.user.id&&!m.read)g.unread++;groups.set(key,g)}res.json({messages:r.rows,conversations:[...groups.values()].sort((a,b)=>new Date(b.lastMessageAt)-new Date(a.lastMessageAt))})}catch(e){sendError(res,e)}});
app.get('/api/admin/messages/unread',admin,async(req,res)=>{try{const r=await q('SELECT COUNT(*) count FROM messages WHERE receiver_id=$1 AND read=false',[req.user.id]);res.json({count:Number(r.rows[0].count),unread:Number(r.rows[0].count)})}catch(e){sendError(res,e)}});
app.get('/api/admin/messages/:id',admin,async(req,res)=>{try{const r=await q('SELECT m.*,s.name sender_name,s.email sender_email,s.avatar sender_avatar FROM messages m LEFT JOIN users s ON s.id=m.sender_id WHERE m.id=$1',[req.params.id]);if(!r.rowCount)return res.status(404).json({error:'Message not found'});await q('UPDATE messages SET read=true WHERE id=$1',[req.params.id]);res.json({message:r.rows[0]})}catch(e){sendError(res,e)}});
app.post('/api/admin/messages/:id',admin,async(req,res)=>{try{const m=await q('SELECT sender_id,receiver_id FROM messages WHERE id=$1',[req.params.id]);if(!m.rowCount)return res.status(404).json({error:'Conversation not found'});const receiver=String(m.rows[0].sender_id)===String(req.user.id)?m.rows[0].receiver_id:m.rows[0].sender_id;const body=clean(req.body.message||req.body.body);if(!body)return res.status(400).json({error:'Message required'});const r=await q('INSERT INTO messages(id,sender_id,receiver_id,body) VALUES($1,$2,$3,$4) RETURNING *',[uid(),req.user.id,receiver,body]);res.status(201).json({message:r.rows[0]})}catch(e){sendError(res,e,400)}});

app.post('/api/uploads',auth,upload.any(),async(req,res)=>{try{const f=(req.files&&req.files[0])||req.file;if(!f)return res.status(400).json({error:'file required'});if(!f.mimetype.startsWith('image/'))return res.status(400).json({error:'Only image files are allowed'});const data=`data:${f.mimetype};base64,${f.buffer.toString('base64')}`;res.status(201).json({url:data,image:data})}catch(e){sendError(res,e,400)}});

async function productCreate(req,res){try{const b=req.body;const p={id:uid(),name:clean(b.name||b.title||b.model)||'Produit',brand:clean(b.brand),category:clean(b.category)||'Téléphone',price:Number(b.price)||0,currency:clean(b.currency)||'USD',stock:Math.max(0,Number(b.stock)||0),image:clean(b.image||b.photo),description:clean(b.description),storage:clean(b.storage),seller_id:req.user.id};const r=await q('INSERT INTO products(id,name,brand,category,price,currency,stock,image,description,storage,seller_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *',[p.id,p.name,p.brand,p.category,p.price,p.currency,p.stock,p.image,p.description,p.storage,p.seller_id]);res.status(201).json({product:r.rows[0]})}catch(e){sendError(res,e,400)}}
app.put('/api/products/:id',admin,async(req,res)=>{try{const b=req.body;const name=clean(b.name||b.title||b.model);const r=await q(`UPDATE products SET
  name=COALESCE(NULLIF($2,''),name),
  brand=COALESCE($3,brand),
  category=COALESCE(NULLIF($4,''),category),
  price=COALESCE($5,price),
  stock=GREATEST(0,COALESCE($6,stock)),
  image=COALESCE(NULLIF($7,''),image),
  description=COALESCE($8,description),
  storage=COALESCE($9,storage),
  updated_at=now()
 WHERE id=$1 RETURNING *`,[req.params.id,name||'',clean(b.brand),clean(b.category),b.price!=null?Number(b.price):null,b.stock!=null?Number(b.stock):null,clean(b.image||b.photo),b.description!=null?clean(b.description):null,b.storage!=null?clean(b.storage):null]);
 if(!r.rowCount)return res.status(404).json({error:'Product not found'});
 res.json({product:r.rows[0]})
}catch(e){sendError(res,e,400)}});
app.delete('/api/products/:id',admin,async(req,res)=>{try{const r=await q('UPDATE products SET active=false,updated_at=now() WHERE id=$1 RETURNING id',[req.params.id]);if(!r.rowCount)return res.status(404).json({error:'Product not found'});res.json({deleted:true,id:req.params.id})}catch(e){sendError(res,e,400)}});
app.post('/api/admin/products',admin,productCreate);
app.post('/api/products',admin,productCreate);
app.patch('/api/admin/products/:id',admin,async(req,res)=>{try{const b=req.body,r=await q('UPDATE products SET name=COALESCE($2,name),brand=COALESCE($3,brand),category=COALESCE($4,category),price=COALESCE($5,price),currency=COALESCE($6,currency),stock=COALESCE($7,stock),image=COALESCE($8,image),description=COALESCE($9,description),storage=COALESCE($10,storage),active=COALESCE($11,active),updated_at=now() WHERE id=$1 RETURNING *',[req.params.id,b.name,b.brand,b.category,b.price,b.currency,b.stock,b.image,b.description,b.storage,b.active]);if(!r.rowCount)return res.status(404).json({error:'Product not found'});res.json({product:r.rows[0]})}catch(e){sendError(res,e,400)}});
app.delete('/api/admin/products/:id',admin,async(req,res)=>{try{const r=await q('UPDATE products SET active=false,updated_at=now() WHERE id=$1 RETURNING *',[req.params.id]);if(!r.rowCount)return res.status(404).json({error:'Product not found'});res.json({ok:true,product:r.rows[0]})}catch(e){sendError(res,e)}});

async function promotionCreate(req,res){try{const b=req.body,r=await q('INSERT INTO promotions(id,title,image,description,active) VALUES($1,$2,$3,$4,$5) RETURNING *',[uid(),clean(b.title),clean(b.image||b.photo),clean(b.description),b.active!==false]);res.status(201).json({promotion:r.rows[0]})}catch(e){sendError(res,e,400)}}
app.post('/api/admin/promotions',admin,promotionCreate);
app.post('/api/promotions',admin,promotionCreate);
app.patch('/api/admin/promotions/:id',admin,async(req,res)=>{try{const b=req.body,r=await q('UPDATE promotions SET title=COALESCE($2,title),image=COALESCE($3,image),description=COALESCE($4,description),active=COALESCE($5,active),updated_at=now() WHERE id=$1 RETURNING *',[req.params.id,b.title,b.image??b.photo,b.description,b.active]);if(!r.rowCount)return res.status(404).json({error:'Promotion not found'});res.json({promotion:r.rows[0]})}catch(e){sendError(res,e,400)}});
app.delete('/api/admin/promotions/:id',admin,async(req,res)=>{try{const r=await q('UPDATE promotions SET active=false,updated_at=now() WHERE id=$1 RETURNING *',[req.params.id]);if(!r.rowCount)return res.status(404).json({error:'Promotion not found'});res.json({ok:true})}catch(e){sendError(res,e)}});

app.get('/api/support/config',async(req,res)=>{try{const r=await q("SELECT value FROM app_settings WHERE key='support'");const v=r.rowCount?r.rows[0].value:{};res.json({enabled:v.enabled!==false,whatsapp:v.whatsapp||process.env.ADMIN_WHATSAPP||''})}catch{res.json({enabled:true,whatsapp:process.env.ADMIN_WHATSAPP||''})}});
app.get('/api/admin/settings/support',admin,async(req,res)=>{const r=await q("SELECT value FROM app_settings WHERE key='support'");res.json({settings:r.rowCount?r.rows[0].value:{enabled:true,whatsapp:process.env.ADMIN_WHATSAPP||''}})});
app.patch('/api/admin/settings/support',admin,async(req,res)=>{const value={enabled:req.body.enabled!==false,whatsapp:clean(req.body.whatsapp||process.env.ADMIN_WHATSAPP)};await q("INSERT INTO app_settings(key,value) VALUES('support',$1) ON CONFLICT(key) DO UPDATE SET value=$1,updated_at=now()",[JSON.stringify(value)]);res.json({settings:value})});
app.get('/api/admin/notifications',admin,async(req,res)=>res.json({notifications:[]}));
app.get('/api/push/public-key',(req,res)=>res.json({publicKey:process.env.PUSH_PUBLIC_KEY||''}));
app.post('/api/push/subscribe',auth,async(req,res)=>{try{if(!req.body||!req.body.endpoint)return res.status(400).json({error:'Push subscription required'});await q('INSERT INTO push_subscriptions(id,user_id,subscription) VALUES($1,$2,$3) ON CONFLICT(user_id) DO UPDATE SET subscription=$3,updated_at=now()',[uid(),req.user.id,JSON.stringify(req.body)]);res.json({ok:true})}catch(e){sendError(res,e,400)}});
app.delete('/api/push/subscribe',auth,async(req,res)=>{await q('DELETE FROM push_subscriptions WHERE user_id=$1',[req.user.id]);res.json({ok:true})});

app.post('/api/streaming-orders',auth,async(req,res)=>{try{const service=String(req.body.service||'').toLowerCase();if(!['netflix','disney'].includes(service))return res.status(400).json({error:'service must be netflix or disney'});const price=Number(req.body.price)||0;const customer=req.body.customer&&typeof req.body.customer==='object'?req.body.customer:{};const r=await q('INSERT INTO streaming_orders(id,user_id,service,plan_id,plan_name,price,currency,customer,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *',[uid(),req.user.id,service,clean(req.body.planId),clean(req.body.planName||req.body.plan),price,clean(req.body.currency)||'USD',JSON.stringify(customer),clean(req.body.status)||'Nouvelle demande']);await q('INSERT INTO notifications(id,user_id,title,body) VALUES($1,$2,$3,$4)',[uid(),req.user.id,'Demande envoyée',`Ta demande ${service==='netflix'?'Netflix':'Disney+'} est en attente de vérification.`]).catch(()=>{});res.status(201).json({order:r.rows[0],streamingOrder:r.rows[0]})}catch(e){sendError(res,e,400)}});
app.get('/api/streaming-orders',auth,async(req,res)=>{try{const r=await q('SELECT * FROM streaming_orders WHERE user_id=$1 ORDER BY created_at DESC',[req.user.id]);res.json({orders:r.rows,streamingOrders:r.rows})}catch(e){sendError(res,e)}});
app.get('/api/admin/streaming-orders',admin,async(req,res)=>{try{const r=await q(`SELECT so.*,u.email customer_email,u.name customer_name FROM streaming_orders so JOIN users u ON u.id=so.user_id ORDER BY so.created_at DESC`);const orders=r.rows.map(o=>({...o,paymentStatus:o.payment_status,planName:o.plan_name,createdAt:o.created_at,price:Number(o.price),customer:{...(o.customer||{}),name:(o.customer||{}).name||o.customer_name,email:(o.customer||{}).email||o.customer_email}}));res.json({orders,streamingOrders:orders,data:orders})}catch(e){sendError(res,e)}});
async function streamingApprove(req,res){const c=await pool.connect();try{await c.query('BEGIN');const r=await c.query("SELECT * FROM streaming_orders WHERE id=$1 FOR UPDATE",[req.params.id]);if(!r.rowCount)throw new Error('Streaming order not found');if(r.rows[0].payment_status!=='pending')throw new Error(`Already ${r.rows[0].payment_status}`);const up=await c.query("UPDATE streaming_orders SET payment_status='paid',status='Confirmée',verified_at=now(),verified_by=$2,updated_at=now() WHERE id=$1 RETURNING *",[req.params.id,req.user.id]);await c.query('INSERT INTO notifications(id,user_id,title,body) VALUES($1,$2,$3,$4)',[uid(),up.rows[0].user_id,'Abonnement confirmé',`Ton abonnement ${up.rows[0].service==='netflix'?'Netflix':'Disney+'} est confirmé.`]).catch(()=>{});await c.query('COMMIT');res.json({order:up.rows[0],status:'paid'})}catch(e){await c.query('ROLLBACK').catch(()=>{});sendError(res,e,400)}finally{c.release()}}
app.post('/api/admin/streaming-orders/:id/approve',admin,streamingApprove);
app.post('/api/admin/streaming-orders/:id/reject',admin,async(req,res)=>{try{const r=await q("UPDATE streaming_orders SET payment_status='rejected',status='Rejetée',verified_at=now(),verified_by=$2,updated_at=now() WHERE id=$1 AND payment_status='pending' RETURNING *",[req.params.id,req.user.id]);if(!r.rowCount)return res.status(400).json({error:'Streaming order not pending'});res.json({order:r.rows[0],status:'rejected'})}catch(e){sendError(res,e,400)}});
app.patch('/api/admin/streaming-orders/:id',admin,async(req,res)=>{if(req.body.status==='paid'||req.body.action==='approve')return streamingApprove(req,res);if(req.body.status==='rejected'||req.body.action==='reject')return app._router.handle({...req,method:'POST',url:`/api/admin/streaming-orders/${req.params.id}/reject`,originalUrl:req.originalUrl},res,()=>{});return res.status(400).json({error:'Use approve or reject streaming order endpoint'})});

app.get('/api/streaming-plans',async(req,res)=>{const r=await q("SELECT value FROM app_settings WHERE key='streaming_plans'");res.json(r.rowCount?r.rows[0].value:{netflix:[],disney:[]})});
app.get('/api/admin/streaming-plans',admin,async(req,res)=>{const r=await q("SELECT value FROM app_settings WHERE key='streaming_plans'");res.json(r.rowCount?r.rows[0].value:{netflix:[],disney:[]})});
app.put('/api/admin/streaming-plans',admin,async(req,res)=>{await q("INSERT INTO app_settings(key,value) VALUES('streaming_plans',$1) ON CONFLICT(key) DO UPDATE SET value=$1,updated_at=now()",[JSON.stringify(req.body)]);res.json({ok:true,data:req.body})});
app.get('/api/settings/trade',async(req,res)=>res.json({enabled:true}));
app.get('/api/admin/settings/trade',admin,async(req,res)=>res.json({enabled:true}));
app.get('/api/trades',auth,async(req,res)=>{const r=await q('SELECT * FROM trades WHERE user_id=$1 ORDER BY created_at DESC',[req.user.id]);res.json({trades:r.rows})});
app.post('/api/trades',auth,async(req,res)=>{try{const r=await q('INSERT INTO trades(id,user_id,product_id,message) VALUES($1,$2,$3,$4) RETURNING *',[uid(),req.user.id,req.body.productId||null,clean(req.body.message)]);res.status(201).json({trade:r.rows[0]})}catch(e){sendError(res,e,400)}});

// Payment providers are deliberately disabled unless credentials are configured. Manual payments remain real and pending.
app.post('/api/payments/stripe/checkout-session',auth,(req,res)=>res.status(501).json({error:'Stripe is not enabled on this backend. Use manual payment or configure STRIPE_SECRET_KEY.'}));
app.get('/api/payments/stripe/session/:id',auth,(req,res)=>res.status(501).json({error:'Stripe is not enabled on this backend.'}));
app.get('/api/payments/stripe/session',auth,(req,res)=>res.status(501).json({error:'Stripe is not enabled on this backend.'}));
const PAYPAL_ENABLED=!!(process.env.PAYPAL_CLIENT_ID&&process.env.PAYPAL_CLIENT_SECRET);
const PAYPAL_API=process.env.PAYPAL_MODE==='live'?'https://api-m.paypal.com':'https://api-m.sandbox.paypal.com';
async function paypalToken(){const r=await fetch(`${PAYPAL_API}/v1/oauth2/token`,{method:'POST',headers:{'Authorization':'Basic '+Buffer.from(`${process.env.PAYPAL_CLIENT_ID}:${process.env.PAYPAL_CLIENT_SECRET}`).toString('base64'),'Content-Type':'application/x-www-form-urlencoded'},body:'grant_type=client_credentials'});const d=await r.json();if(!r.ok)throw new Error(d.error_description||'PayPal auth failed');return d.access_token;}
app.post('/api/payments/paypal/create-order',auth,async(req,res)=>{
 if(!PAYPAL_ENABLED)return res.status(501).json({error:'PayPal is not enabled on this backend. Configure PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET first.'});
 const c=await pool.connect();
 try{
  const raw=normalizeItems(req.body.items);const {out,total,currency}=await priceCart(raw,c.query.bind(c));
  await c.query('BEGIN');const oid=uid();
  await c.query('INSERT INTO orders(id,customer_id,items,total,currency,payment_method) VALUES($1,$2,$3,$4,$5,$6)',[oid,req.user.id,JSON.stringify(out),total,currency,'paypal']);
  await c.query('COMMIT');
  const token=await paypalToken();
  const pp=await fetch(`${PAYPAL_API}/v2/checkout/orders`,{method:'POST',headers:{'Authorization':`Bearer ${token}`,'Content-Type':'application/json'},body:JSON.stringify({intent:'CAPTURE',purchase_units:[{reference_id:oid,amount:{currency_code:currency,value:total.toFixed(2)}}],application_context:{return_url:req.body.returnUrl,cancel_url:req.body.cancelUrl}})});
  const ppData=await pp.json();
  if(!pp.ok)throw new Error(ppData.message||'PayPal order creation failed');
  await q('UPDATE orders SET payment_method=$2 WHERE id=$1',[oid,'paypal:'+ppData.id]);
  res.status(201).json({id:ppData.id,orderId:oid,internalOrderId:oid,links:ppData.links});
 }catch(e){await c.query('ROLLBACK').catch(()=>{});sendError(res,e,400)}finally{c.release()}
});
async function paypalCapture(req,res){
 if(!PAYPAL_ENABLED)return res.status(501).json({error:'PayPal is not enabled on this backend.'});
 const paypalOrderId=req.body.paypalOrderId||req.body.orderID||req.body.token;
 if(!paypalOrderId)return res.status(400).json({error:'paypalOrderId required'});
 const c=await pool.connect();
 try{
  const token=await paypalToken();
  const cap=await fetch(`${PAYPAL_API}/v2/checkout/orders/${paypalOrderId}/capture`,{method:'POST',headers:{'Authorization':`Bearer ${token}`,'Content-Type':'application/json'}});
  const capData=await cap.json();
  if(!cap.ok||capData.status!=='COMPLETED')throw new Error(capData.message||'PayPal capture not completed');
  const internalOrderId=req.body.orderId||capData.purchase_units?.[0]?.reference_id;
  if(!internalOrderId)throw new Error('Missing internal order reference');
  await c.query('BEGIN');
  const o=await c.query('SELECT * FROM orders WHERE id=$1 AND customer_id=$2 FOR UPDATE',[internalOrderId,req.user.id]);
  if(!o.rowCount)throw new Error('Order not found');
  const order=o.rows[0];
  if(order.payment_status!=='paid'){
   const items=Array.isArray(order.items)?order.items:[];
   for(const item of items){const n=Number(item.quantity||1);const s=await c.query('UPDATE products SET stock=stock-$2,updated_at=now() WHERE id=$1 AND active=true AND stock >= $2 RETURNING id',[item.productId,n]);if(!s.rowCount)throw new Error(`Insufficient stock for product ${item.productId}`)}
   await c.query("UPDATE orders SET payment_status='paid',status=CASE WHEN status='En attente' THEN 'Confirmée' ELSE status END,updated_at=now() WHERE id=$1",[internalOrderId]);
   await c.query('INSERT INTO payments(id,order_id,customer_id,payment_method,amount,currency,transaction_reference,status,verified_at) VALUES($1,$2,$3,$4,$5,$6,$7,\'paid\',now())',[uid(),internalOrderId,req.user.id,'paypal',order.total,order.currency,paypalOrderId]);
  }
  await c.query('COMMIT');
  res.json({status:'paid',orderId:internalOrderId,paypal:capData});
 }catch(e){await c.query('ROLLBACK').catch(()=>{});sendError(res,e,400)}finally{c.release()}
}
app.post('/api/payments/paypal/capture-order',auth,paypalCapture);
app.post('/api/payments/paypal/capture',auth,paypalCapture); // alias: matches the path this frontend build actually calls
app.post('/api/chatbot',auth,async(req,res)=>res.json({reply:'Support automatique indisponible pour le moment. Vous pouvez contacter un administrateur.',needsAdmin:true,conversationId:null,severity:'normal'}));

app.use((req,res)=>res.status(404).json({error:'Route not found',path:req.path,method:req.method}));
app.use((err,req,res,next)=>{console.error(err);res.status(500).json({error:'Server error'})});

init().then(()=>app.listen(PORT,()=>console.log(`ZhuoMarket backend v2.0.0 listening on ${PORT}`))).catch(e=>{console.error('BOOT ERROR',e);process.exit(1)});
