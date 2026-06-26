/**
 * 灵犀笔记 - Node.js 后端 API 服务
 * 替代 FastAPI 版本，使用 JSON 文件存储（免编译依赖）
 */
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 8080;

// ── 中间件 ────────────────────────────────────────────────
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json({ limit: '50mb' }));

// 静态文件
const frontendDir = path.join(__dirname, '..', 'deploy');
if (fs.existsSync(frontendDir)) {
  app.use(express.static(frontendDir));
}

// ── 数据存储（JSON 文件）─────────────────────────────────
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const DB = {
  reflections: path.join(DATA_DIR, 'reflections.json'),
  tasks: path.join(DATA_DIR, 'tasks.json'),
  projects: path.join(DATA_DIR, 'projects.json'),
  emotions: path.join(DATA_DIR, 'emotions.json'),
  pushSubs: path.join(DATA_DIR, 'push_subscriptions.json'),
  settings: path.join(DATA_DIR, 'settings.json'),
};

function loadJSON(file) {
  try {
    if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, 'utf-8'));
  } catch (e) { console.error(`Load ${file} error:`, e.message); }
  return file.endsWith('settings.json') ? {} : [];
}

function saveJSON(file, data) {
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf-8');
  fs.renameSync(tmp, file);
}

function reloadAndSave(file, fn) {
  const data = loadJSON(file);
  const result = fn(data);
  saveJSON(file, data);
  return result;
}

// ── 工具函数 ──────────────────────────────────────────────
function nowISO() { return new Date().toISOString(); }
function hashPwd(p) { return crypto.createHash('sha256').update(p + 'lingxi-salt-2026').digest('hex'); }

// ── VAPID 密钥 ────────────────────────────────────────────
function getOrCreateVAPID() {
  const settings = loadJSON(DB.settings);
  if (settings.vapid_private) {
    return { publicKey: settings.vapid_public, privateKey: settings.vapid_private };
  }
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });
  const pubB64 = Buffer.from(publicKey).toString('base64url');
  const privB64 = Buffer.from(privateKey).toString('base64url');
  settings.vapid_public = pubB64;
  settings.vapid_private = privB64;
  saveJSON(DB.settings, settings);
  return { publicKey: pubB64, privateKey: privB64 };
}

// Initialize VAPID on startup
getOrCreateVAPID();

// ── 认证中间件 ────────────────────────────────────────────
function requireAuth(req, res, next) {
  const settings = loadJSON(DB.settings);
  const storedHash = settings.password_hash;
  if (!storedHash) return next(); // 未设置密码

  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: '需要认证' });
  }
  if (auth.slice(7) !== storedHash) {
    return res.status(403).json({ error: '认证失败' });
  }
  next();
}

// ── 密码管理 ──────────────────────────────────────────────
app.post('/api/auth/setup', (req, res) => {
  const { password } = req.body;
  if (!password || password.length < 4) return res.status(400).json({ error: '密码至少4位' });
  const settings = loadJSON(DB.settings);
  const h = hashPwd(password);
  settings.password_hash = h;
  saveJSON(DB.settings, settings);
  res.json({ ok: true, token: h, message: '密码已设置' });
});

app.post('/api/auth/verify', (req, res) => {
  const { password } = req.body;
  const settings = loadJSON(DB.settings);
  const stored = settings.password_hash;
  if (!stored) return res.json({ ok: true, token: '', message: '未设置密码' });
  const h = hashPwd(password);
  if (h !== stored) return res.status(403).json({ error: '密码错误' });
  res.json({ ok: true, token: h, message: '验证通过' });
});

// ── 感悟 API ──────────────────────────────────────────────
app.get('/api/reflections', requireAuth, (req, res) => {
  let items = loadJSON(DB.reflections).filter(r => !r.deleted);
  const { date_from, date_to, tag } = req.query;

  if (date_from) items = items.filter(r => r.created_at >= date_from);
  if (date_to) items = items.filter(r => r.created_at <= date_to + 'T23:59:59');
  if (tag) items = items.filter(r => r.tags && r.tags.includes(tag));

  items.sort((a, b) => b.created_at.localeCompare(a.created_at));

  const page = parseInt(req.query.page) || 1;
  const pageSize = Math.min(parseInt(req.query.page_size) || 50, 200);
  const offset = (page - 1) * pageSize;
  res.json({ items: items.slice(offset, offset + pageSize), total: items.length, page, page_size: pageSize });
});

app.get('/api/reflections/calendar', requireAuth, (req, res) => {
  const { year, month } = req.query;
  const start = `${year}-${String(month).padStart(2, '0')}-01`;
  const endMonth = parseInt(month) === 12 ? 1 : parseInt(month) + 1;
  const endYear = parseInt(month) === 12 ? parseInt(year) + 1 : year;
  const end = `${endYear}-${String(endMonth).padStart(2, '0')}-01`;

  const items = loadJSON(DB.reflections).filter(r => !r.deleted && r.created_at >= start && r.created_at < end);
  const dayMap = {};
  items.forEach(r => {
    const d = r.created_at.substring(0, 10);
    dayMap[d] = (dayMap[d] || 0) + 1;
  });
  res.json(Object.entries(dayMap).map(([date, count]) => ({ date, count })));
});

app.post('/api/reflections', requireAuth, (req, res) => {
  const data = req.body;
  const item = reloadAndSave(DB.reflections, (items) => {
    const now = nowISO();
    const rec = {
      id: data.id || uuidv4(),
      content: data.content,
      tags: data.tags || [],
      mood: data.mood || '',
      source: data.source || '',
      created_at: data.created_at || now,
      updated_at: now,
      device_id: data.device_id || '',
      deleted: 0,
    };
    items.push(rec);
    return rec;
  });
  res.json(item);
});

app.put('/api/reflections/:id', requireAuth, (req, res) => {
  const result = reloadAndSave(DB.reflections, (items) => {
    const idx = items.findIndex(r => r.id === req.params.id && !r.deleted);
    if (idx === -1) return null;
    const data = req.body;
    const now = nowISO();
    if (data.content !== undefined) items[idx].content = data.content;
    if (data.tags !== undefined) items[idx].tags = data.tags;
    if (data.mood !== undefined) items[idx].mood = data.mood;
    if (data.source !== undefined) items[idx].source = data.source;
    items[idx].updated_at = now;
    return items[idx];
  });
  if (!result) return res.status(404).json({ error: '记录不存在' });
  res.json(result);
});

app.delete('/api/reflections/:id', requireAuth, (req, res) => {
  const result = reloadAndSave(DB.reflections, (items) => {
    const idx = items.findIndex(r => r.id === req.params.id && !r.deleted);
    if (idx === -1) return false;
    items[idx].deleted = 1;
    items[idx].updated_at = nowISO();
    return true;
  });
  if (!result) return res.status(404).json({ error: '记录不存在' });
  res.json({ ok: true });
});

// ── 任务 API ──────────────────────────────────────────────
app.get('/api/tasks', requireAuth, (req, res) => {
  let items = loadJSON(DB.tasks).filter(t => !t.deleted);
  const { status, due_date, project_id } = req.query;

  if (status === 'active') items = items.filter(t => !t.completed);
  else if (status === 'completed') items = items.filter(t => t.completed);
  if (due_date) items = items.filter(t => t.due_date === due_date);
  if (project_id !== undefined) {
    if (project_id === '') items = items.filter(t => !t.project_id);
    else items = items.filter(t => t.project_id === project_id);
  }

  items.sort((a, b) => b.priority - a.priority || (a.due_date || '').localeCompare(b.due_date || '') || b.created_at.localeCompare(a.created_at));

  const page = parseInt(req.query.page) || 1;
  const pageSize = Math.min(parseInt(req.query.page_size) || 100, 200);
  const offset = (page - 1) * pageSize;
  res.json({ items: items.slice(offset, offset + pageSize), total: items.length, page, page_size: pageSize });
});

app.post('/api/tasks', requireAuth, (req, res) => {
  const data = req.body;
  const item = reloadAndSave(DB.tasks, (items) => {
    const now = nowISO();
    const rec = {
      id: data.id || uuidv4(),
      title: data.title,
      description: data.description || '',
      due_date: data.due_date || null,
      priority: data.priority || 0,
      completed: data.completed || false,
      completed_at: data.completed ? (data.completed_at || now) : null,
      reminder_time: data.reminder_time || null,
      project_id: data.project_id || '',
      created_at: data.created_at || now,
      updated_at: now,
      device_id: data.device_id || '',
      deleted: 0,
    };
    items.push(rec);
    return rec;
  });
  res.json(item);
});

app.put('/api/tasks/:id', requireAuth, (req, res) => {
  const result = reloadAndSave(DB.tasks, (items) => {
    const idx = items.findIndex(t => t.id === req.params.id && !t.deleted);
    if (idx === -1) return null;
    const data = req.body;
    const now = nowISO();
    if (data.title !== undefined) items[idx].title = data.title;
    if (data.description !== undefined) items[idx].description = data.description;
    if (data.due_date !== undefined) items[idx].due_date = data.due_date;
    if (data.priority !== undefined) items[idx].priority = data.priority;
    if (data.reminder_time !== undefined) items[idx].reminder_time = data.reminder_time;
    if (data.project_id !== undefined) items[idx].project_id = data.project_id;
    if (data.completed !== undefined) {
      items[idx].completed = data.completed;
      items[idx].completed_at = data.completed ? (data.completed_at || now) : null;
    }
    items[idx].updated_at = now;
    return items[idx];
  });
  if (!result) return res.status(404).json({ error: '任务不存在' });
  res.json(result);
});

app.delete('/api/tasks/:id', requireAuth, (req, res) => {
  const result = reloadAndSave(DB.tasks, (items) => {
    const idx = items.findIndex(t => t.id === req.params.id && !t.deleted);
    if (idx === -1) return false;
    items[idx].deleted = 1;
    items[idx].updated_at = nowISO();
    return true;
  });
  if (!result) return res.status(404).json({ error: '任务不存在' });
  res.json({ ok: true });
});

// ── 项目 API ──────────────────────────────────────────────
app.get('/api/projects', requireAuth, (req, res) => {
  const projects = loadJSON(DB.projects).filter(p => !p.deleted);
  const tasks = loadJSON(DB.tasks).filter(t => !t.deleted);
  const result = projects.map(p => ({
    ...p,
    task_count: tasks.filter(t => t.project_id === p.id).length,
    done_count: tasks.filter(t => t.project_id === p.id && t.completed).length,
  }));
  result.sort((a, b) => (a.sort_order || 0) - (b.sort_order || 0) || b.created_at.localeCompare(a.created_at));
  res.json(result);
});

app.post('/api/projects', requireAuth, (req, res) => {
  const data = req.body;
  const item = reloadAndSave(DB.projects, (items) => {
    const now = nowISO();
    const rec = {
      id: data.id || uuidv4(),
      name: data.name,
      color: data.color || '#8B7355',
      description: data.description || '',
      sort_order: data.sort_order || 0,
      created_at: data.created_at || now,
      updated_at: now,
      device_id: data.device_id || '',
      deleted: 0,
    };
    items.push(rec);
    return rec;
  });
  res.json(item);
});

app.put('/api/projects/:id', requireAuth, (req, res) => {
  const result = reloadAndSave(DB.projects, (items) => {
    const idx = items.findIndex(p => p.id === req.params.id && !p.deleted);
    if (idx === -1) return null;
    const data = req.body;
    if (data.name !== undefined) items[idx].name = data.name;
    if (data.color !== undefined) items[idx].color = data.color;
    if (data.description !== undefined) items[idx].description = data.description;
    if (data.sort_order !== undefined) items[idx].sort_order = data.sort_order;
    items[idx].updated_at = nowISO();
    return items[idx];
  });
  if (!result) return res.status(404).json({ error: '项目不存在' });
  res.json(result);
});

app.delete('/api/projects/:id', requireAuth, (req, res) => {
  let found = false;
  reloadAndSave(DB.projects, (items) => {
    const idx = items.findIndex(p => p.id === req.params.id && !p.deleted);
    if (idx === -1) return;
    items[idx].deleted = 1;
    items[idx].updated_at = nowISO();
    found = true;
  });
  if (found) {
    reloadAndSave(DB.tasks, (items) => {
      items.forEach(t => { if (t.project_id === req.params.id) t.project_id = ''; });
    });
    return res.json({ ok: true });
  }
  res.status(404).json({ error: '项目不存在' });
});

// ── 同步 API ──────────────────────────────────────────────
app.post('/api/merge', requireAuth, (req, res) => {
  const { device_id, reflections = [], tasks = [], projects = [], emotions = [] } = req.body;
  const serverTime = nowISO();

  // 合并感悟
  reloadAndSave(DB.reflections, (existing) => {
    reflections.forEach(r => {
      const rid = r.id || uuidv4();
      const found = existing.find(e => e.id === rid);
      if (found && r.updated_at && found.updated_at >= r.updated_at) return;
      const ts = r.updated_at || serverTime;
      const rec = {
        id: rid, content: r.content, tags: r.tags || [], mood: r.mood || '',
        source: r.source || '', created_at: r.created_at || ts, updated_at: ts,
        device_id: r.device_id || device_id, deleted: 0,
      };
      if (found) Object.assign(found, rec);
      else existing.push(rec);
    });
  });

  // 合并任务
  reloadAndSave(DB.tasks, (existing) => {
    tasks.forEach(t => {
      const tid = t.id || uuidv4();
      const found = existing.find(e => e.id === tid);
      if (found && t.updated_at && found.updated_at >= t.updated_at) return;
      const ts = t.updated_at || serverTime;
      const rec = {
        id: tid, title: t.title, description: t.description || '', due_date: t.due_date || null,
        priority: t.priority || 0, status: t.status || (t.completed ? 'done' : 'todo'),
        completed: t.completed || false,
        completed_at: t.completed ? (t.completed_at || ts) : null,
        notes: t.notes || [],
        reminder_time: t.reminder_time || null, project_id: t.project_id || '',
        created_at: t.created_at || ts, updated_at: ts,
        device_id: t.device_id || device_id, deleted: 0,
      };
      if (found) Object.assign(found, rec);
      else existing.push(rec);
    });
  });

  // 合并项目
  reloadAndSave(DB.projects, (existing) => {
    projects.forEach(p => {
      const pid = p.id || uuidv4();
      const found = existing.find(e => e.id === pid);
      if (found && p.updated_at && found.updated_at >= p.updated_at) return;
      const ts = p.updated_at || serverTime;
      const rec = {
        id: pid, name: p.name, color: p.color || '#8B7355', description: p.description || '',
        sort_order: p.sort_order || 0, created_at: p.created_at || ts, updated_at: ts,
        device_id: p.device_id || device_id, deleted: 0,
      };
      if (found) Object.assign(found, rec);
      else existing.push(rec);
    });
  });

  // 合并情绪
  reloadAndSave(DB.emotions, (existing) => {
    emotions.forEach(e => {
      const eid = e.id || uuidv4();
      const found = existing.find(ex => ex.id === eid);
      if (found && e.updated_at && found.updated_at >= e.updated_at) return;
      const ts = e.updated_at || serverTime;
      const rec = {
        id: eid, emotion: e.emotion, description: e.description || '',
        intensity: e.intensity || 3, created_at: e.created_at || ts, updated_at: ts,
        device_id: e.device_id || device_id, deleted: 0,
      };
      if (found) Object.assign(found, rec);
      else existing.push(rec);
    });
  });

  // 返回全量数据
  const allRef = loadJSON(DB.reflections).filter(r => !r.deleted);
  const allTasks = loadJSON(DB.tasks).filter(t => !t.deleted);
  const allProjects = loadJSON(DB.projects).filter(p => !p.deleted);
  const allEmotions = loadJSON(DB.emotions).filter(e => !e.deleted);

  res.json({
    reflections: allRef.sort((a, b) => b.created_at.localeCompare(a.created_at)),
    tasks: allTasks.sort((a, b) => b.priority - a.priority || (a.due_date || '').localeCompare(b.due_date || '')),
    projects: allProjects.sort((a, b) => (a.sort_order || 0) - (b.sort_order || 0)),
    emotions: allEmotions.sort((a, b) => b.created_at.localeCompare(a.created_at)),
    server_time: serverTime,
  });
});

// ── Push 通知 API ─────────────────────────────────────────
app.get('/api/push/vapid-public-key', (req, res) => {
  res.json({ public_key: getOrCreateVAPID().publicKey });
});

app.post('/api/push/subscribe', requireAuth, (req, res) => {
  const { device_id, endpoint, p256dh, auth } = req.body;
  const sub = reloadAndSave(DB.pushSubs, (subs) => {
    const rec = { id: uuidv4(), device_id, endpoint, p256dh, auth, created_at: nowISO(), updated_at: nowISO() };
    // Replace existing subscription for same endpoint
    const existIdx = subs.findIndex(s => s.endpoint === endpoint);
    if (existIdx >= 0) {
      subs[existIdx] = rec;
    } else {
      subs.push(rec);
    }
    return rec;
  });
  res.json({ ok: true, id: sub.id });
});

app.post('/api/push/unsubscribe', requireAuth, (req, res) => {
  reloadAndSave(DB.pushSubs, (subs) => {
    const idx = subs.findIndex(s => s.endpoint === req.body.endpoint);
    if (idx >= 0) subs.splice(idx, 1);
  });
  res.json({ ok: true });
});

// 发送 Web Push 通知（简化版，使用标准 Web Push 协议）
async function sendWebPush(sub, payload) {
  try {
    const keys = getOrCreateVAPID();
    const endpoint = sub.endpoint;

    // VAPID JWT
    const header = { typ: 'JWT', alg: 'ES256' };
    const aud = new URL(endpoint).origin;
    const claims = {
      aud,
      exp: Math.floor(Date.now() / 1000) + 86400,
      sub: 'mailto:lingxi@notes.app',
    };
    const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
    const claimsB64 = Buffer.from(JSON.stringify(claims)).toString('base64url');
    const signingInput = `${headerB64}.${claimsB64}`;

    const sign = crypto.createSign('SHA256');
    sign.update(signingInput);
    sign.end();
    const signature = sign.sign({ key: crypto.createPrivateKey({
      key: Buffer.from(keys.privateKey, 'base64url'), format: 'der', type: 'pkcs8',
    }), dsaEncoding: 'ieee-p1363' });
    // Convert IEEE P1363 to DER for ES256
    const sigLen = signature.length / 2;
    const r = signature.subarray(0, sigLen);
    const s = signature.subarray(sigLen);
    const derSignature = Buffer.concat([
      Buffer.from([0x30, signature.length + 4, 0x02, sigLen]),
      r[0] & 0x80 ? Buffer.concat([Buffer.from([0x00]), r]) : r,
      Buffer.from([0x02, sigLen]),
      s[0] & 0x80 ? Buffer.concat([Buffer.from([0x00]), s]) : s,
    ]);
    const sigB64 = derSignature.toString('base64url');
    const vapidToken = `${signingInput}.${sigB64}`;

    const pushData = JSON.stringify(payload);
    const resp = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        'TTL': '86400',
        'Authorization': `vapid t=${vapidToken}, k=${keys.publicKey}`,
        'Urgency': 'high',
      },
      body: pushData,
    });
    return resp.ok;
  } catch (e) {
    console.error('Push error:', e.message);
    return false;
  }
}

app.post('/api/push/send-reminders', requireAuth, async (req, res) => {
  const subs = loadJSON(DB.pushSubs);
  if (subs.length === 0) return res.json({ sent: 0, message: '没有活跃的推送订阅' });

  const tasks = loadJSON(DB.tasks).filter(t => !t.deleted && !t.completed);
  const today = new Date().toISOString().substring(0, 10);
  const todayTasks = tasks.filter(t => !t.due_date || t.due_date === today).slice(0, 10);

  const hasUrgent = todayTasks.some(t => t.priority === 2);
  const title = todayTasks.length > 0
    ? (hasUrgent ? '🔴 今日有紧急任务' : `📋 今日还有 ${todayTasks.length} 个任务`)
    : '📋 今日工作提醒';
  const body = todayTasks.length > 0
    ? (todayTasks.length === 1 ? todayTasks[0].title : `包括「${todayTasks[0].title}」等 ${todayTasks.length} 项`)
    : '今天还没有待办任务，规划一下吧';

  let sent = 0;
  for (const sub of subs) {
    if (await sendWebPush(sub, { title, body, tag: 'lingxi-daily' })) sent++;
  }
  res.json({ sent, total_subs: subs.length });
});

// ── 周总结 API ────────────────────────────────────────────
app.get('/api/summary/weekly', requireAuth, (req, res) => {
  const weekStart = req.query.week_start;
  let ws;
  if (weekStart) {
    ws = new Date(weekStart);
  } else {
    const today = new Date();
    ws = new Date(today);
    ws.setDate(today.getDate() - today.getDay() + (today.getDay() === 0 ? -6 : 1)); // Monday
  }
  ws.setHours(0, 0, 0, 0);
  const we = new Date(ws);
  we.setDate(ws.getDate() + 6);
  we.setHours(23, 59, 59, 999);

  const wsISO = ws.toISOString().substring(0, 10);
  const weISO = we.toISOString().substring(0, 10);

  const reflections = loadJSON(DB.reflections).filter(r => {
    if (r.deleted) return false;
    const d = r.created_at.substring(0, 10);
    return d >= wsISO && d <= weISO;
  }).sort((a, b) => b.created_at.localeCompare(a.created_at));

  // 按天分组
  const daily = {};
  reflections.forEach(r => {
    const d = r.created_at.substring(0, 10);
    if (!daily[d]) daily[d] = [];
    daily[d].push(r);
  });

  // 心情统计
  const moodCounts = {};
  reflections.forEach(r => { if (r.mood) moodCounts[r.mood] = (moodCounts[r.mood] || 0) + 1; });

  // 简单关键词提取
  const stopWords = new Set(['的','了','是','在','我','有','和','就','不','人','都','一','一个','上','也','很','到','说','要','去','你','会','着','没有','看','好','自己','这','他','她','它','们','那']);
  const wordFreq = {};
  reflections.forEach(r => {
    const text = r.content;
    for (const n of [2, 3, 4]) {
      for (let i = 0; i <= text.length - n; i++) {
        const w = text.substring(i, i + n);
        if (!stopWords.has(w) && /[\u4e00-\u9fff]/.test(w)) {
          wordFreq[w] = (wordFreq[w] || 0) + 1;
        }
      }
    }
  });
  const topKeywords = Object.entries(wordFreq).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([w, c]) => ({ word: w, count: c }));

  let highlight = '';
  if (reflections.length > 0) {
    const longest = reflections.reduce((a, b) => a.content.length > b.content.length ? a : b);
    highlight = longest.content.substring(0, 200);
  }

  res.json({
    week_start: wsISO,
    week_end: weISO,
    total_reflections: reflections.length,
    daily_breakdown: Object.entries(daily).sort().map(([d, items]) => ({ date: d, count: items.length, items })),
    mood_summary: moodCounts,
    top_keywords: topKeywords,
    highlight_text: highlight,
  });
});

// ── 统计 API ──────────────────────────────────────────────
app.get('/api/stats', requireAuth, (req, res) => {
  const reflections = loadJSON(DB.reflections).filter(r => !r.deleted);
  const tasks = loadJSON(DB.tasks).filter(t => !t.deleted);
  const completed = tasks.filter(t => t.completed);

  // 最近 7 天
  const sevenDaysAgo = new Date();
  sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
  const recent = {};
  reflections
    .filter(r => r.created_at >= sevenDaysAgo.toISOString())
    .forEach(r => {
      const d = r.created_at.substring(0, 10);
      recent[d] = (recent[d] || 0) + 1;
    });

  const today = new Date().toISOString().substring(0, 10);
  const todayUndone = tasks.filter(t => !t.completed && (!t.due_date || t.due_date === today));

  const moodStats = {};
  reflections.forEach(r => { if (r.mood) moodStats[r.mood] = (moodStats[r.mood] || 0) + 1; });

  res.json({
    total_reflections: reflections.length,
    total_tasks: tasks.length,
    completed_tasks: completed.length,
    recent_daily: Object.entries(recent).sort().map(([d, c]) => ({ date: d, count: c })),
    today_undone_tasks: todayUndone,
    mood_stats: Object.entries(moodStats).sort((a, b) => b[1] - a[1]).map(([m, c]) => ({ mood: m, count: c })),
  });
});

// ── Health ─────────────────────────────────────────────────
app.get('/api/health', (req, res) => res.json({ status: 'ok', time: nowISO() }));

// ── Fallback: serve frontend ──────────────────────────────
app.use((req, res) => {
  const indexPath = path.join(frontendDir, 'index.html');
  if (fs.existsSync(indexPath)) return res.sendFile(indexPath);
  res.json({ message: '灵犀笔记 API 服务运行中' });
});

// ── 启动 ──────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log(`灵犀笔记 API 服务已启动: http://0.0.0.0:${PORT}`);
  console.log(`数据目录: ${DATA_DIR}`);
});
