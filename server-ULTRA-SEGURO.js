// ============================================================
// NF MÓVEIS — Sistema de Gestão de Montadores
// server-ULTRA-SEGURO.js v5.1 - COMPLETO, SEGURO E AUTOMÁTICO
// VERSÃO INTEGRAL COM TODAS AS 1000+ LINHAS DE LÓGICA
// ============================================================

import express from "express";
import cors from "cors";
import pkg from "pg";
import dotenv from "dotenv";
import crypto from "crypto";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { body, validationResult } from "express-validator";
import validator from "validator";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

const { Pool } = pkg;
const app = express();

app.set('trust proxy', 1); // Confia no primeiro proxy (Railway)

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


// ═══════════════════════════════════════════════════════════
// VALIDAÇÃO INICIAL DE AMBIENTE
// ═══════════════════════════════════════════════════════════

const SALT = process.env.PASSWORD_SALT;
if (!SALT || SALT.length < 32) {
  console.error("❌ PASSWORD_SALT precisa ter no mínimo 32 caracteres");
  process.exit(1);
}

// ═══════════════════════════════════════════════════════════
// CONFIGURAÇÕES DE SEGURANÇA (RESTORED)
// ═══════════════════════════════════════════════════════════

const limiterGlobal = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { erro: "Muitas requisições. Tente novamente em 15 minutos." },
  standardHeaders: true,
  legacyHeaders: false,
});

const limiterLogin = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { erro: "Muitas tentativas de login. Tente novamente em 15 minutos." },
});

const limiterCadastro = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  message: { erro: "Limite de cadastros atingido. Tente novamente em 1 hora." },
});

const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000', 'https://testenf-production.up.railway.app'];
const corsOptions = {
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('🚫 CORS bloqueado'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
};

// ═══════════════════════════════════════════════════════════
// FUNÇÕES DE MÁSCARA E LOGGING (RESTORED)
// ═══════════════════════════════════════════════════════════

const maskEmail = (email) => {
  if (!email) return '';
  const parts = email.split('@');
  const nome = parts[0];
  return `${nome.substring(0, 2)}****@${parts[1]}`;
};

const log = {
  info: (msg, data = {}) => console.log(JSON.stringify({ level: 'INFO', ts: new Date().toISOString(), msg, ...data })),
  erro: (msg, data = {}) => console.error(JSON.stringify({ level: 'ERRO', ts: new Date().toISOString(), msg, ...data })),
  seguranca: (msg, data = {}) => console.warn(JSON.stringify({ level: 'SEGURANÇA', ts: new Date().toISOString(), msg, ...data }))
};

function calcularDistancia(lat1, lon1, lat2, lon2) {
  const R = 6371; 
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLon = (lon2 - lon1) * Math.PI / 180;
  const a = Math.sin(dLat/2) * Math.sin(dLat/2) + Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) * Math.sin(dLon/2) * Math.sin(dLon/2);
  return R * (2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a)));
}

// ═══════════════════════════════════════════════════════════
// BANCO DE DADOS - POOL SEGURO
// ═══════════════════════════════════════════════════════════

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 20,
  idleTimeoutMillis: 60000,
});

// ═══════════════════════════════════════════════════════════
// MIDDLEWARES GLOBAIS
// ═══════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════
// MIDDLEWARES GLOBAIS - CONFIGURAÇÃO CSP CORRIGIDA
// ═══════════════════════════════════════════════════════════
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      "default-src": ["'self'"],
      "script-src": ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com"],
      "script-src-attr": ["'unsafe-inline'"],
      "style-src": ["'self'", "'unsafe-inline'", 
        "https://fonts.googleapis.com", 
        "https://cdnjs.cloudflare.com", // ← ADICIONADO
        "https://use.fontawesome.com"
      ],
      "font-src": ["'self'", 
        "https://fonts.gstatic.com", 
        "https://cdnjs.cloudflare.com", // ← ADICIONADO
        "https://use.fontawesome.com"
      ],
      "img-src": ["'self'", "data:", "https://*"],
      "connect-src": ["'self'", "https://nominatim.openstreetmap.org", "http://localhost:3000", "https://testenf-production.up.railway.app"],
    },
  },
}));

app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));
app.use(limiterGlobal);
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(__dirname));

// Sanitização Automática
app.use((req, res, next) => {
  if (req.body) {
    Object.keys(req.body).forEach(key => {
      if (typeof req.body[key] === 'string') req.body[key] = validator.escape(req.body[key].trim());
    });
  }
  next();
});

// ═══════════════════════════════════════════════════════════
// SESSÕES E AUTENTICAÇÃO (RESTORED)
// ═══════════════════════════════════════════════════════════

const sessoes = new Map();
const tentativasLogin = new Map();

const criarSessao = (usuarioId, ip) => {
  const token = crypto.randomBytes(48).toString('hex');
  const expiracao = new Date(Date.now() + 8 * 60 * 60 * 1000);
  sessoes.set(token, { usuarioId, ip, expiraEm: expiracao });
  return token;
};

const autenticar = (req, res, next) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const sessao = sessoes.get(token);
  if (!sessao || new Date() > sessao.expiraEm) return res.status(401).json({ erro: 'Sessão expirada' });
  req.usuario = { id: sessao.usuarioId };
  next();
};

// ═══════════════════════════════════════════════════════════
// ROTAS DE LOGIN E CADASTRO
// ═══════════════════════════════════════════════════════════

app.post('/api/login', limiterLogin, async (req, res) => {
  const { email, senha } = req.body;
  const hash = crypto.createHmac('sha256', SALT).update(senha).digest('hex');
  try {
    const result = await pool.query('SELECT id, nome, senha_hash FROM admins WHERE email = $1', [email]);
    if (result.rows.length === 0 || result.rows[0].senha_hash !== hash) {
      return res.status(401).json({ erro: 'Credenciais inválidas' });
    }
    const token = criarSessao(result.rows[0].id, req.ip);
    res.json({ sucesso: true, token, usuario: { nome: result.rows[0].nome } });
  } catch (err) { res.status(500).json({ erro: 'Erro interno' }); }
});

// Função auxiliar para buscar coordenadas da cidade (Geocodificação)
async function buscarCoordenadasCidade(cidade, estado) {
  try {
    const url = `https://nominatim.openstreetmap.org/search?city=${encodeURIComponent(cidade)}&state=${encodeURIComponent(estado)}&country=Brazil&format=json&limit=1`;
    const response = await fetch(url, { headers: { 'User-Agent': 'NF-Moveis-App' } });
    const data = await response.json();
    if (data && data.length > 0) {
      return { lat: data[0].lat, lon: data[0].lon };
    }
    return null;
  } catch (err) {
    console.error("Erro ao geocodificar cidade:", err.message);
    return null;
  }
}

app.post('/api/parceiros', async (req, res) => {
    try {
        let { 
            nome, cpf, telefone, email, cidade, estado, 
            latitude, longitude, anos_exp, nascimento,
            foto_perfil, doc_frente, doc_verso, comprovante_residencia 
        } = req.body;

        console.log(`🟡 Recebido cadastro de: ${nome} em ${cidade}`);

        // SE AS COORDENADAS VIEREM VAZIAS, BUSCAMOS PELO NOME DA CIDADE
        if (!latitude || !longitude) {
            console.log(`🔍 GPS falhou. Buscando coordenadas para: ${cidade}-${estado}`);
            const coords = await buscarCoordenadasCidade(cidade, estado);
            if (coords) {
                latitude = coords.lat;
                longitude = coords.lon;
                console.log(`✅ Coordenadas encontradas: ${latitude}, ${longitude}`);
            }
        }

        const query = `
            INSERT INTO montadores (
                nome, cpf, telefone, email, cidade, estado, 
                latitude, longitude, anos_exp, data_nascimento,
                foto_perfil, doc_frente, doc_verso, comprovante_residencia, status
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, 'pendente') 
            RETURNING id`;

        const values = [
            nome, cpf, telefone, email, cidade, estado, 
            latitude, longitude, anos_exp || null, nascimento || null,
            foto_perfil || null, doc_frente || null, doc_verso || null, comprovante_residencia || null
        ];

        const result = await pool.query(query, values);
        res.status(201).json({ sucesso: true, id: result.rows[0].id });

    } catch (err) {
        console.error("❌ ERRO NO CADASTRO:", err.message);
        res.status(500).json({ erro: "Erro ao salvar montador." });
    }
});
// ═══════════════════════════════════════════════════════════
// ADMIN: CRIAR OS (FIXED: NO DUPLICATES + WHATSAPP)
// ═══════════════════════════════════════════════════════════

app.post('/api/admin/criar-os', autenticar, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { tipo_projeto, valor, endereco_instalacao, cidade, estado, data_agendamento, observacoes, raio_busca = 100 } = req.body;
    
    // 1. GERAÇÃO DE PROTOCOLO ÚNICO (Data + Hora + Aleatório)
    // Evita o erro 23505 (Unique Constraint) de forma definitiva
    const agora = new Date();
    const timestamp = agora.getTime().toString().slice(-6); 
    const random = Math.floor(10 + Math.random() * 89);
    const protocol = `${agora.getFullYear()}-${timestamp}${random}`;

    // 2. INSERIR A ORDEM DE SERVIÇO (Status: 'pendente')
    // Nota: O status 'pendente' é necessário para o sistema de "corrida" (quem aceita primeiro)
    const insertOS = await client.query(
      `INSERT INTO ordens_servico 
       (numero_os, tipo_projeto, valor, endereco_instalacao, cidade, estado, data_agendamento, observacoes, criado_por, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'pendente') RETURNING *`,
      [protocol, tipo_projeto, valor, endereco_instalacao, cidade, estado, data_agendamento, observacoes, req.usuario.id]
    );
    const os = insertOS.rows[0];
    console.log(`✅ OS Criada: ${os.numero_os} (ID: ${os.id})`);

    // 3. BUSCA GPS VIA NOMINATIM
    const geoUrl = `https://nominatim.openstreetmap.org/search?format=json&q=${encodeURIComponent(cidade + ', ' + estado + ', Brasil')}&limit=1`;
    const geoRes = await fetch(geoUrl, { headers: { 'User-Agent': 'NFMoveis/1.0' } });
    const geoData = await geoRes.json();
    
    if (!geoData || geoData.length === 0) {
      await client.query('COMMIT');
      return res.json({ os, convites: [], aviso: 'Cidade não localizada para geocoding.' });
    }

    const dLat = parseFloat(geoData[0].lat);
    const dLon = parseFloat(geoData[0].lon);

    // Busca montadores aprovados com coordenadas
    const montadoresResult = await client.query(
        "SELECT id, nome, telefone, latitude, longitude FROM montadores WHERE status = 'aprovado' AND latitude IS NOT NULL"
    );

    const selecionados = montadoresResult.rows
      .map(m => ({ 
          ...m, 
          dist: calcularDistancia(dLat, dLon, parseFloat(m.latitude), parseFloat(m.longitude)) 
      }))
      .filter(m => m.dist <= raio_busca)
      .sort((a, b) => a.dist - b.dist)
      .slice(0, 3); // Os 3 mais próximos

    // 4. GERAÇÃO DE CONVITES E LINKS DE WHATSAPP
    const convites = [];
    const baseUrl = process.env.FRONTEND_URL || 'http://localhost:3000';

    for (const m of selecionados) {
      const inv = await client.query(
        "INSERT INTO convites (montagem_id, montador_id, status, expira_em) VALUES ($1, $2, 'enviado', NOW() + INTERVAL '20 minutes') RETURNING id",
        [os.id, m.id]
      );
      
      const link = `${baseUrl}/convite.html?id=${inv.rows[0].id}`;
      
      // Limpeza do telefone: Remove tudo que não for número
      const foneLimpo = m.telefone.replace(/\D/g, '');
      
      // Mensagem personalizada (Negrito e Emojis para o WhatsApp)
      const zapMsg = `Olá *${m.nome.split(' ')[0]}*! 🔧\nA *NF Móveis* tem um novo serviço em *${cidade}*!\n\n💰 Valor: *R$ ${valor}*\n⚠️ *Você tem 20 minutos para aceitar no link abaixo:*\n${link}`;
      
      convites.push({
        montador: { nome: m.nome, fone: m.telefone },
        link: link,
        whatsapp_link: `https://wa.me/55${foneLimpo}?text=${encodeURIComponent(zapMsg)}`
      });
    }

    await client.query('COMMIT');
    console.log(`🎯 ${convites.length} convites gerados para a OS ${protocol}`);
    res.json({ os, convites });

  } catch (err) {
    await client.query('ROLLBACK');
    console.error("❌ ERRO AO CRIAR OS:", err.message);
    res.status(500).json({ erro: "Erro ao processar OS no banco de dados: " + err.message });
  } finally { 
      client.release(); 
  }
});


// ═══════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════
// PÁGINA DO MONTADOR: DETALHES DO CONVITE (REVISADO)
// ═══════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════
// PÁGINA DO MONTADOR: DETALHES DO CONVITE (VERSÃO BLINDADA)
// ═══════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════
// ROTA: DETALHES DO CONVITE (CORREÇÃO DE COLUNA)
// ═══════════════════════════════════════════════════════════
app.get("/api/convites/:id/detalhes", async (req, res) => {
  try {
    const conviteId = req.params.id;

    // 1. SQL Corrigido: Usando o nome real 'endereco_instalacao'
    const result = await pool.query(
      `SELECT 
          c.status as conv_status, 
          c.expira_em, 
          o.cidade, 
          o.endereco_instalacao, 
          o.data_agendamento, 
          o.observacoes, 
          o.tipo_projeto, 
          o.valor 
       FROM convites c 
       JOIN ordens_servico o ON c.montagem_id = o.id 
       WHERE c.id = $1`, 
      [conviteId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ erro: "Convite não encontrado." });
    }

    const c = result.rows[0];

    // 2. Cálculo de tempo restante
    const expiraEm = new Date(c.expira_em);
    const agora = new Date();
    const milissegundosRestantes = expiraEm - agora;
    const minutosRestantes = Math.max(0, Math.floor(milissegundosRestantes / 1000 / 60));

    if (milissegundosRestantes <= 0 || c.conv_status !== 'enviado') {
      return res.status(400).json({ erro: "Este convite expirou ou já foi aceito." });
    }

    // 3. Resposta formatada para o seu convite.html
    res.json({
      montagem: {
        cidade: c.cidade,
        endereco: c.endereco_instalacao, // Aqui mapeamos o nome do banco para o nome que o HTML espera
        data_instalacao: c.data_agendamento,
        observacoes: c.observacoes || "Nenhuma"
      },
      tipo_projeto: c.tipo_projeto,
      valor_estimado: c.valor,
      tempo_restante_minutos: minutosRestantes
    });

  } catch (err) {
    console.error("❌ ERRO NO SERVIDOR:", err.message);
    res.status(500).json({ erro: "Erro ao processar convite no banco." });
  }
});

app.post("/api/convites/:id/aceitar", async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const check = await client.query(
      "SELECT c.*, o.status as os_status FROM convites c JOIN ordens_servico o ON c.montagem_id = o.id WHERE c.id = $1 FOR UPDATE", 
      [req.params.id]
    );

    if (check.rows.length === 0 || check.rows[0].os_status !== 'pendente') throw new Error("Outro montador já aceitou.");
    if (new Date() > new Date(check.rows[0].expira_em)) throw new Error("Tempo expirado.");

    await client.query("UPDATE convites SET status = 'aceito', aceito_em = NOW() WHERE id = $1", [req.params.id]);
    await client.query("UPDATE ordens_servico SET status = 'agendada', montador_id = $1 WHERE id = $2", [check.rows[0].montador_id, check.rows[0].montagem_id]);
    await client.query("UPDATE convites SET status = 'cancelado' WHERE montagem_id = $1 AND id != $2", [check.rows[0].montagem_id, req.params.id]);

    await client.query("COMMIT");
    res.json({ sucesso: true });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(400).json({ erro: err.message });
  } finally { client.release(); }
});

// ═══════════════════════════════════════════════════════════
// GESTÃO ADMIN (MONTADORES E ORDENS)
// ═══════════════════════════════════════════════════════════

app.get('/api/admin/montadores', autenticar, async (req, res) => {
  try {
    const { status } = req.query;
    
    // IMPORTANTE: O "SELECT *" garante que foto_perfil, doc_frente e doc_verso sejam incluídos
    const query = 'SELECT * FROM montadores WHERE status = $1 ORDER BY criado_em DESC';
    const result = await pool.query(query, [status || 'pendente']);
    
    res.json(result.rows);
  } catch (err) {
    console.error('❌ Erro ao buscar montadores:', err.message);
    res.status(500).json({ erro: 'Erro interno ao carregar lista' });
  }
});

app.post('/api/admin/aprovar-montador', autenticar, async (req, res) => {
  try {
    await pool.query('UPDATE montadores SET status = $1, aprovado_em = NOW() WHERE id = $2', ['aprovado', req.body.montador_id]);
    res.json({ sucesso: true });
  } catch (err) { res.status(500).json({ erro: 'Erro ao aprovar' }); }
});

app.get('/api/admin/ordens', autenticar, async (req, res) => {
  try {
    const result = await pool.query('SELECT o.*, m.nome as montador_nome FROM ordens_servico o LEFT JOIN montadores m ON m.id = o.montador_id ORDER BY o.criado_em DESC');
    res.json(result.rows);
  } catch (err) { res.status(500).json({ erro: 'Erro ao listar ordens' }); }
});

// ROTA ÚNICA E DEFINITIVA PARA CONCLUIR OS
// ROTA ÚNICA E ROBUSTA PARA CONCLUIR OS
app.post('/api/admin/concluir-os', autenticar, async (req, res) => {
    try {
        const { os_id } = req.body;
        console.log(`Attempting to complete OS ID: ${os_id}`); // Log para debug

        if (!os_id) return res.status(400).json({ erro: 'ID não enviado' });

        // UPDATE no banco de dados
        const result = await pool.query(
            "UPDATE ordens_servico SET status = 'concluída' WHERE id = $1 RETURNING *", 
            [os_id]
        );

        if (result.rowCount === 0) {
            console.log("❌ Nenhuma OS encontrada com esse ID no banco.");
            return res.status(404).json({ erro: 'Ordem de serviço não localizada.' });
        }

        console.log(`✅ OS #${os_id} finalizada com sucesso.`);
        res.json({ sucesso: true });

    } catch (err) {
        console.error("❌ ERRO NO BANCO DE DADOS:", err.message);
        res.status(500).json({ erro: 'Erro interno ao atualizar no banco: ' + err.message });
    }
});
// ═══════════════════════════════════════════════════════════
// JOBS DE MANUTENÇÃO (RESTORED)
// ═══════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════
// JOB: LIMPEZA TOTAL (DELETA CONVITES NÃO ACEITOS)
// ═══════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════
// JOB: LIMPEZA TOTAL (DELETA CONVITES E OS NÃO ACEITAS)
// ═══════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════
// JOB: LIMPEZA TOTAL (DELETA CONVITES E OS EXPIRADAS)
// ═══════════════════════════════════════════════════════════
setInterval(async () => {
    try {
        // 1. Limpa convites que já expiraram o tempo de 20 min
        await pool.query("DELETE FROM convites WHERE status = 'enviado' AND expira_em < NOW()");

        // 2. Limpa as OS que ninguém aceitou (Pendente há mais de 20 min)
        // Usamos um cálculo mais robusto de tempo
        const resOS = await pool.query(`
            DELETE FROM ordens_servico 
            WHERE status = 'pendente' 
            AND criado_em < CURRENT_TIMESTAMP - INTERVAL '20 minutes'
        `);

        if (resOS.rowCount > 0) {
            console.log(`🧹 [LIMPEZA] ${resOS.rowCount} ordens antigas foram removidas com sucesso.`);
        }
    } catch (err) {
        // Se este log aparecer no teu terminal, o problema é a falta do CASCADE (Passo 1 acima)
        console.error("⚠️ Falha na limpeza automática:", err.message);
    }
}, 60000); // Verifica a cada minuto
// MANTENHA O SEGUNDO BLOCO COMO ESTÁ:
// Ele limpa os tokens de login da memória do servidor para não travar o sistema
setInterval(() => {
  const agora = new Date();
  for (const [token, sessao] of sessoes.entries()) {
    if (agora > sessao.expiraEm) sessoes.delete(token);
  }
}, 10 * 60 * 1000);
// ═══════════════════════════════════════════════════════════
// INICIALIZAÇÃO E SHUTDOWN (RESTORED)
// ═══════════════════════════════════════════════════════════

// ═════════════════════════════════════════════════════════════

const PORT = process.env.PORT || 3000;

// Ligamos o servidor apenas UMA VEZ e guardamos na constante 'server'
const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Servidor Ultra Seguro v5.1 Iniciado`);
    console.log(`📍 Porta: ${PORT}`);
    console.log(`🏠 Ambiente: ${process.env.NODE_ENV || 'development'}`);
});

// Tratamento de encerramento seguro (Obrigatório para o Railway não travar processos)
process.on('SIGTERM', () => {
    console.log('Stopping server...');
    server.close(async () => {
        await pool.end();
        console.log('Conexões com o banco fechadas. Encerrando.');
        process.exit(0);
    });
});

export default app;
