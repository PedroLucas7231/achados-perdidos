'use strict';

const express = require('express');
const cors    = require('cors');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const path    = require('path');

const app    = express();
const PORT   = process.env.PORT || 3000;
const SECRET = 'faseh-2026-segredo';

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ── Banco em memória ──────────────────────────────────────────
let usuarios = [
  { id:1, nome:'Admin FASEH', email:'admin@ulife.com.br', senha:bcrypt.hashSync('01/01/1980',10), tipo:'admin', criado_em:new Date().toISOString() },
  { id:2, nome:'Pedro Lucas', email:'pedro@ulife.com.br', senha:bcrypt.hashSync('15/08/2000',10), tipo:'aluno', criado_em:new Date().toISOString() },
  { id:3, nome:'Ana Souza',   email:'ana@ulife.com.br',   senha:bcrypt.hashSync('23/10/2001',10), tipo:'aluno', criado_em:new Date().toISOString() },
];
let itens = [
  { id:1, usuario_id:2, usuario_nome:'Pedro Lucas', descricao:'Carteira preta de couro', categoria:'Documentos',  local:'Biblioteca — 2º andar', data_ocorrencia:'2026-05-15', status:'perdido',    tipo:'perdido',    obs:'Contém RG e CPF.', foto:'', criado_em:new Date().toISOString() },
  { id:2, usuario_id:3, usuario_nome:'Ana Souza',   descricao:'Chave com chaveiro azul', categoria:'Chaves',      local:'Bloco A — Sala 3',      data_ocorrencia:'2026-05-14', status:'encontrado', tipo:'encontrado', obs:'', foto:'', criado_em:new Date().toISOString() },
  { id:3, usuario_id:2, usuario_nome:'Pedro Lucas', descricao:'Celular Samsung Galaxy',  categoria:'Eletrônicos', local:'Cantina',               data_ocorrencia:'2026-05-13', status:'encontrado', tipo:'encontrado', obs:'', foto:'', criado_em:new Date().toISOString() },
  { id:4, usuario_id:2, usuario_nome:'Pedro Lucas', descricao:'Mochila azul',            categoria:'Bolsas',      local:'Corredor Bloco B',      data_ocorrencia:'2026-05-12', status:'perdido',    tipo:'perdido',    obs:'Mochila Mormaii.', foto:'', criado_em:new Date().toISOString() },
  { id:5, usuario_id:3, usuario_nome:'Ana Souza',   descricao:'Óculos de grau',          categoria:'Acessórios',  local:'Sala 204',              data_ocorrencia:'2026-05-10', status:'devolvido',  tipo:'perdido',    obs:'', foto:'', criado_em:new Date().toISOString() },
];
let notificacoes = [
  { id:1, usuario_id:2, mensagem:'Item compatível: <strong>Chave com chaveiro azul</strong>.', icon:'ti-key',    lida:0, criado_em:new Date().toISOString() },
  { id:2, usuario_id:2, mensagem:'Sua <strong>Carteira preta</strong> recebeu uma solicitação.', icon:'ti-wallet', lida:0, criado_em:new Date().toISOString() },
];
let nextId = { usuario:4, item:6, notif:3 };

// ── Validação ─────────────────────────────────────────────────
function validDate(s) {
  return /^\d{2}\/\d{2}\/\d{4}$/.test(s);
}
function isAdult(s) {
  const [d,m,y] = s.split('/').map(Number);
  const birth = new Date(y, m-1, d);
  const today = new Date();
  let age = today.getFullYear() - birth.getFullYear();
  if (today.getMonth() < birth.getMonth() ||
     (today.getMonth() === birth.getMonth() && today.getDate() < birth.getDate())) age--;
  return age >= 18;
}

// ── Auth Middleware ───────────────────────────────────────────
function authMW(req, res, next) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer ')) return res.status(401).json({ error:'Não autorizado.' });
  try {
    req.user = jwt.verify(h.split(' ')[1], SECRET);
    next();
  } catch {
    res.status(401).json({ error:'Sessão expirada.' });
  }
}
function adminMW(req, res, next) {
  authMW(req, res, () => {
    if (req.user.tipo !== 'admin') return res.status(403).json({ error:'Acesso negado.' });
    next();
  });
}

// ══ AUTH ══════════════════════════════════════════════════════
app.post('/api/auth/register', (req, res) => {
  const { nome, email, senha } = req.body;
  if (!nome || !nome.trim())             return res.status(400).json({ error:'Informe seu nome.' });
  if (!email || !email.endsWith('@ulife.com.br')) return res.status(400).json({ error:'Use @ulife.com.br.' });
  if (!validDate(senha))                 return res.status(400).json({ error:'Use DD/MM/AAAA.' });
  if (!isAdult(senha))                   return res.status(400).json({ error:'É necessário ter 18 anos ou mais.' });
  const emailLower = email.toLowerCase();
  if (usuarios.find(u => u.email === emailLower)) return res.status(409).json({ error:'E-mail já cadastrado.' });
  const user = {
    id: nextId.usuario++,
    nome: nome.trim(),
    email: emailLower,
    senha: bcrypt.hashSync(senha, 10),
    tipo: 'aluno',
    criado_em: new Date().toISOString()
  };
  usuarios.push(user);
  const { senha:_, ...safe } = user;
  const token = jwt.sign({ id:safe.id, nome:safe.nome, email:safe.email, tipo:safe.tipo }, SECRET, { expiresIn:'7d' });
  res.status(201).json({ token, user:safe });
});

app.post('/api/auth/login', (req, res) => {
  const { email, senha } = req.body;
  const emailLower = (email || '').toLowerCase();
  const user = usuarios.find(u => u.email === emailLower);
  if (!user || !bcrypt.compareSync(senha, user.senha))
    return res.status(401).json({ error:'E-mail ou data de nascimento incorretos.' });
  const { senha:_, ...safe } = user;
  const token = jwt.sign({ id:safe.id, nome:safe.nome, email:safe.email, tipo:safe.tipo }, SECRET, { expiresIn:'7d' });
  res.json({ token, user:safe });
});

app.get('/api/auth/me', authMW, (req, res) => {
  const user = usuarios.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error:'Não encontrado.' });
  const { senha:_, ...safe } = user;
  res.json(safe);
});

// ══ ITENS ═════════════════════════════════════════════════════
app.get('/api/items', (req, res) => {
  const { search, status, from, to, sort } = req.query;
  let result = itens.slice();
  if (search) {
    const s = search.toLowerCase();
    result = result.filter(i =>
      i.descricao.toLowerCase().includes(s) ||
      i.local.toLowerCase().includes(s) ||
      i.categoria.toLowerCase().includes(s)
    );
  }
  if (status && status !== 'todos') result = result.filter(i => i.status === status);
  if (from) result = result.filter(i => !i.data_ocorrencia || i.data_ocorrencia >= from);
  if (to)   result = result.filter(i => !i.data_ocorrencia || i.data_ocorrencia <= to);
  if      (sort === 'oldest') result.sort((a,b) => a.criado_em.localeCompare(b.criado_em));
  else if (sort === 'az')     result.sort((a,b) => a.descricao.localeCompare(b.descricao, 'pt'));
  else if (sort === 'cat')    result.sort((a,b) => a.categoria.localeCompare(b.categoria, 'pt'));
  else                        result.sort((a,b) => b.criado_em.localeCompare(a.criado_em));
  res.json(result);
});

app.post('/api/items', authMW, (req, res) => {
  const { descricao, categoria, local, data_ocorrencia, tipo, obs, foto } = req.body;
  if (!descricao || !descricao.trim()) return res.status(400).json({ error:'Informe a descrição.' });
  if (!categoria)                      return res.status(400).json({ error:'Selecione a categoria.' });
  if (!local || !local.trim())         return res.status(400).json({ error:'Informe o local.' });
  const item = {
    id: nextId.item++,
    usuario_id: req.user.id,
    usuario_nome: req.user.nome,
    descricao: descricao.trim(),
    categoria,
    local: local.trim(),
    data_ocorrencia: data_ocorrencia || null,
    status: tipo || 'perdido',
    tipo: tipo || 'perdido',
    obs: obs || '',
    foto: foto || '',
    criado_em: new Date().toISOString()
  };
  itens.unshift(item);
  usuarios.filter(u => u.tipo === 'admin').forEach(a => {
    notificacoes.unshift({ id:nextId.notif++, usuario_id:a.id, mensagem:`Novo registro: <strong>${descricao}</strong> por ${req.user.nome}.`, icon:'ti-package', lida:0, criado_em:new Date().toISOString() });
  });
  res.status(201).json(item);
});

app.put('/api/items/:id', authMW, (req, res) => {
  const item = itens.find(i => i.id === parseInt(req.params.id));
  if (!item) return res.status(404).json({ error:'Item não encontrado.' });
  if (item.usuario_id !== req.user.id && req.user.tipo !== 'admin')
    return res.status(403).json({ error:'Sem permissão.' });
  const { descricao, categoria, local, data_ocorrencia, obs } = req.body;
  if (descricao)                 item.descricao = descricao;
  if (categoria)                 item.categoria = categoria;
  if (local)                     item.local = local;
  if (data_ocorrencia !== undefined) item.data_ocorrencia = data_ocorrencia;
  if (obs !== undefined)         item.obs = obs;
  res.json(item);
});

app.delete('/api/items/:id', authMW, (req, res) => {
  const idx = itens.findIndex(i => i.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ error:'Item não encontrado.' });
  if (itens[idx].usuario_id !== req.user.id && req.user.tipo !== 'admin')
    return res.status(403).json({ error:'Sem permissão.' });
  itens.splice(idx, 1);
  res.json({ ok:true });
});

app.get('/api/my-items', authMW, (req, res) => {
  res.json(itens.filter(i => i.usuario_id === req.user.id).sort((a,b) => b.criado_em.localeCompare(a.criado_em)));
});

app.post('/api/items/:id/claim', authMW, (req, res) => {
  const item = itens.find(i => i.id === parseInt(req.params.id));
  if (!item) return res.status(404).json({ error:'Item não encontrado.' });
  usuarios.filter(u => u.tipo === 'admin').forEach(a => {
    notificacoes.unshift({ id:nextId.notif++, usuario_id:a.id, mensagem:`Reivindicação: <strong>${item.descricao}</strong> por ${req.user.nome}.`, icon:'ti-check', lida:0, criado_em:new Date().toISOString() });
  });
  res.json({ ok:true });
});

// ══ NOTIFICAÇÕES ══════════════════════════════════════════════
app.get('/api/notifications', authMW, (req, res) => {
  res.json(notificacoes.filter(n => n.usuario_id === req.user.id).sort((a,b) => b.criado_em.localeCompare(a.criado_em)));
});

app.post('/api/notifications/read-all', authMW, (req, res) => {
  notificacoes.filter(n => n.usuario_id === req.user.id).forEach(n => { n.lida = 1; });
  res.json({ ok:true });
});

// ══ ADMIN ═════════════════════════════════════════════════════
app.get('/api/admin/stats', adminMW, (req, res) => {
  res.json({
    items:       itens.length,
    perdidos:    itens.filter(i => i.status === 'perdido').length,
    encontrados: itens.filter(i => i.status === 'encontrado').length,
    devolvidos:  itens.filter(i => i.status === 'devolvido').length,
    usuarios:    usuarios.length,
  });
});

app.get('/api/admin/items', adminMW, (req, res) => {
  res.json(itens.slice().sort((a,b) => b.criado_em.localeCompare(a.criado_em)));
});

app.put('/api/admin/items/:id/status', adminMW, (req, res) => {
  const item = itens.find(i => i.id === parseInt(req.params.id));
  if (!item) return res.status(404).json({ error:'Item não encontrado.' });
  item.status = req.body.status;
  const msgs  = { perdido:'foi marcado como perdido', encontrado:'foi encontrado!', devolvido:'foi marcado como devolvido ✓' };
  const icons = { perdido:'ti-alert-circle', encontrado:'ti-search', devolvido:'ti-circle-check' };
  notificacoes.unshift({ id:nextId.notif++, usuario_id:item.usuario_id, mensagem:`Seu item <strong>${item.descricao}</strong> ${msgs[req.body.status]}.`, icon:icons[req.body.status], lida:0, criado_em:new Date().toISOString() });
  res.json({ ok:true });
});

app.get('/api/admin/users', adminMW, (req, res) => {
  res.json(usuarios.map(({ senha:_, ...u }) => u));
});

app.get('/api/admin/export', adminMW, (req, res) => {
  const csv = 'ID,Descrição,Categoria,Local,Data,Status,Registrado por\n' +
    itens.map(i => `${i.id},"${i.descricao}","${i.categoria}","${i.local}","${i.data_ocorrencia||''}","${i.status}","${i.usuario_nome}"`).join('\n');
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="achados_perdidos.csv"');
  res.send('\uFEFF' + csv);
});

// ── Fallback → index.html ─────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Iniciar servidor ──────────────────────────────────────────
app.listen(PORT, () => {
  console.log('\n=================================');
  console.log('  Achados & Perdidos — FASEH');
  console.log('  Servidor rodando na porta ' + PORT);
  console.log('=================================\n');
  console.log('  pedro@ulife.com.br / 15/08/2000');
  console.log('  admin@ulife.com.br / 01/01/1980\n');
});
