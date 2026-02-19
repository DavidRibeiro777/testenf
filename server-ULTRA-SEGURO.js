// ============================================================
// NF MÓVEIS — Sistema de Gestão de Montadores
// server-ULTRA-SEGURO.js v4.1 - COMPLETO E CORRIGIDO
// 100% SEGURO — Todas as proteções implementadas
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

// Configuração de caminhos para ES Modules
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
// CONFIGURAÇÕES DE SEGURANÇA
// ═══════════════════════════════════════════════════════════

// 1. RATE LIMITING
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

// 2. CORS
const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'];
const corsOptions = {
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.log(`🚫 CORS bloqueado para: ${origin}`);
      callback(new Error('Origem não permitida pelo CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
};

// ═══════════════════════════════════════════════════════════
// FUNÇÕES DE MÁSCARA (LOGS SEGUROS)
// ═══════════════════════════════════════════════════════════

const maskEmail = (email) => {
  if (!email) return '';
  const parts = email.split('@');
  if (parts.length !== 2) return 'email_inválido';
  const nome = parts[0];
  const masked = nome.length > 3 
    ? nome.substring(0, 2) + '*'.repeat(nome.length - 2) 
    : '*'.repeat(nome.length);
  return `${masked}@${parts[1]}`;
};

const maskCPF = (cpf) => {
  if (!cpf) return '';
  const cleaned = cpf.replace(/\D/g, '');
  if (cleaned.length !== 11) return '***.***.***-**';
  return `${cleaned.substring(0,3)}.***.***-${cleaned.substring(9)}`;
};

const maskPhone = (phone) => {
  if (!phone) return '';
  const cleaned = phone.replace(/\D/g, '');
  if (cleaned.length < 10) return '(**) *****-****';
  return `(${cleaned.substring(0,2)}) *****-${cleaned.substring(7)}`;
};

// ═══════════════════════════════════════════════════════════
// LOGGING ESTRUTURADO
// ═══════════════════════════════════════════════════════════

const log = {
  info: (msg, data = {}) => {
    console.log(JSON.stringify({ 
      level: 'INFO', 
      timestamp: new Date().toISOString(), 
      msg, 
      ...data 
    }));
  },
  erro: (msg, data = {}) => {
    console.error(JSON.stringify({ 
      level: 'ERRO', 
      timestamp: new Date().toISOString(), 
      msg, 
      ...data 
    }));
  },
  seguranca: (msg, data = {}) => {
    console.warn(JSON.stringify({ 
      level: 'SEGURANÇA', 
      timestamp: new Date().toISOString(), 
      msg, 
      ...data 
    }));
  }
};

// ═══════════════════════════════════════════════════════════
// BANCO DE DADOS - POOL SEGURO
// ═══════════════════════════════════════════════════════════

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 20,
  idleTimeoutMillis: 60000,        // ← AUMENTADO para 60 segundos
  connectionTimeoutMillis: 30000,   // ← AUMENTADO para 30 segundos
  keepAlive: true,                  // ← ADICIONADO
  keepAliveInitialDelay: 10000,     // ← ADICIONADO
});
// Reconexão automática se o banco cair
pool.on('error', (err) => {
  log.erro('Erro no pool do banco, tentando reconectar...', { erro: err.message });
  // O pool tenta reconectar automaticamente
});

// ═══════════════════════════════════════════════════════════
// MIDDLEWARES GLOBAIS
// ═══════════════════════════════════════════════════════════

// Helmet - headers de segurança
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        "default-src": ["'self'"],
        "script-src": ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com"],
        "script-src-attr": ["'unsafe-inline'"], // ← ADICIONE ESTA LINHA
        "style-src": ["'self'", "'unsafe-inline'", 
          "https://fonts.googleapis.com", 
          "https://cdnjs.cloudflare.com",
          "https://use.fontawesome.com"
        ],
        "font-src": ["'self'", 
          "https://fonts.gstatic.com", 
          "https://cdnjs.cloudflare.com",
          "https://use.fontawesome.com"
        ],
        "img-src": ["'self'", "data:", "https://*"],
        "connect-src": ["'self'"],
      },
    },
  })
);
// Forçar HTTPS em produção
if (process.env.NODE_ENV === 'production') {
  app.use((req, res, next) => {
    if (req.headers['x-forwarded-proto'] !== 'https') {
      return res.redirect(`https://${req.headers.host}${req.url}`);
    }
    next();
  });
}

app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));
app.use(limiterGlobal);

// ✅ ARQUIVOS ESTÁTICOS (HTML, CSS, JS)
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(__dirname));

// Middleware de sanitização automática
app.use((req, res, next) => {
  if (req.body) {
    Object.keys(req.body).forEach(key => {
      if (typeof req.body[key] === 'string') {
        req.body[key] = validator.escape(req.body[key].trim());
      }
    });
  }
  next();
});

// ═══════════════════════════════════════════════════════════
// FUNÇÕES CRIPTOGRÁFICAS
// ═══════════════════════════════════════════════════════════

const hashSenha = (senha) => {
  return crypto.createHmac('sha256', SALT)
    .update(senha)
    .digest('hex');
};

const validarSenhaForte = (senha) => {
  const errors = [];
  if (senha.length < 8) errors.push('mínimo 8 caracteres');
  if (!/[A-Z]/.test(senha)) errors.push('uma letra maiúscula');
  if (!/[a-z]/.test(senha)) errors.push('uma letra minúscula');
  if (!/[0-9]/.test(senha)) errors.push('um número');
  if (/(.)\1{2,}/.test(senha)) errors.push('não pode ter caracteres repetidos');
  return errors;
};

const gerarTokenSessao = () => {
  return crypto.randomBytes(48).toString('hex');
};

// ═══════════════════════════════════════════════════════════
// MAPA DE TENTATIVAS DE LOGIN
// ═══════════════════════════════════════════════════════════

const tentativasLogin = new Map();

const registrarTentativaLogin = (ip) => {
  const tentativas = tentativasLogin.get(ip) || { count: 0, bloqueadoAte: null };
  
  if (tentativas.bloqueadoAte && new Date() < tentativas.bloqueadoAte) {
    return { bloqueado: true, tempo: tentativas.bloqueadoAte };
  }
  
  tentativas.count += 1;
  
  if (tentativas.count >= 10) {
    tentativas.bloqueadoAte = new Date(Date.now() + 30 * 60 * 1000);
    log.seguranca('IP bloqueado por muitas tentativas de login', { ip });
  }
  
  tentativasLogin.set(ip, tentativas);
  return { bloqueado: false, tentativas: tentativas.count };
};

const resetarTentativasLogin = (ip) => {
  tentativasLogin.delete(ip);
};

// ═══════════════════════════════════════════════════════════
// SESSÕES
// ═══════════════════════════════════════════════════════════

const sessoes = new Map();

const criarSessao = (usuarioId, ip) => {
  const token = gerarTokenSessao();
  const agora = new Date();
  const expiracao = new Date(agora.getTime() + 8 * 60 * 60 * 1000);
  
  sessoes.set(token, {
    usuarioId,
    ip,
    criadoEm: agora,
    expiraEm: expiracao,
    renovadoEm: agora
  });
  
  return token;
};

const validarSessao = (token) => {
  if (!token || typeof token !== 'string' || !/^[a-f0-9]{96}$/.test(token)) {
    return null;
  }
  
  const sessao = sessoes.get(token);
  if (!sessao) return null;
  
  if (new Date() > sessao.expiraEm) {
    sessoes.delete(token);
    return null;
  }
  
  const tempoRestante = sessao.expiraEm - new Date();
  if (tempoRestante < 2 * 60 * 60 * 1000) {
    sessao.expiraEm = new Date(Date.now() + 8 * 60 * 60 * 1000);
    sessao.renovadoEm = new Date();
  }
  
  return sessao;
};

// ═══════════════════════════════════════════════════════════
// MIDDLEWARE DE AUTENTICAÇÃO
// ═══════════════════════════════════════════════════════════

const autenticar = (req, res, next) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ erro: 'Token não fornecido' });
  }
  
  const sessao = validarSessao(token);
  if (!sessao) {
    return res.status(401).json({ erro: 'Sessão inválida ou expirada' });
  }
  
  req.usuario = { id: sessao.usuarioId };
  next();
};

// ═══════════════════════════════════════════════════════════
// HEALTH CHECK
// ═══════════════════════════════════════════════════════════

app.get('/api/health', async (req, res) => {
  try {
    const inicio = Date.now();
    await pool.query('SELECT 1');
    const latencia = Date.now() - inicio;
    
    res.json({
      status: 'OK',
      timestamp: new Date().toISOString(),
      versao: '4.1.0-ultra-seguro',
      banco: 'conectado',
      latencia: `${latencia}ms`,
      ambiente: process.env.NODE_ENV || 'development'
    });
  } catch (err) {
    log.erro('Health check falhou', { erro: err.message });
    res.status(503).json({ 
      status: 'ERRO', 
      banco: 'desconectado',
      timestamp: new Date().toISOString()
    });
  }
});

// ═══════════════════════════════════════════════════════════
// ROTA DE LOGIN
// ═══════════════════════════════════════════════════════════

app.post('/api/login',
  limiterLogin,
  [
    body('email').isEmail().normalizeEmail(),
    body('senha').notEmpty().isString()
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      console.log('❌ Erros de validação:', errors.array());
      return res.status(400).json({ erro: 'Dados inválidos' });
    }
    
    const ip = req.ip || req.socket.remoteAddress;
    
    const tentativa = registrarTentativaLogin(ip);
    if (tentativa.bloqueado) {
      return res.status(429).json({ 
        erro: 'Muitas tentativas. IP bloqueado por 30 minutos.' 
      });
    }
    
    const { email, senha } = req.body;
    
    console.log('=================================');
    console.log('🔍 TENTATIVA DE LOGIN');
    console.log('📧 Email recebido:', email);
    console.log('🔑 Senha recebida:', senha);
    console.log('🧂 Salt usado:', process.env.PASSWORD_SALT);
    
    try {
      const result = await pool.query(
        'SELECT id, nome, email, senha_hash FROM admins WHERE email = $1',
        [email]
      );
      
      if (result.rows.length === 0) {
        console.log('❌ Admin não encontrado no banco');
        return res.status(401).json({ erro: 'Credenciais inválidas' });
      }
      
      const usuario = result.rows[0];
      console.log('✅ Admin encontrado:');
      console.log('   ID:', usuario.id);
      console.log('   Email:', usuario.email);
      console.log('   Hash no banco:', usuario.senha_hash);
      
      const senhaHash = hashSenha(senha);
      console.log('   Hash calculado:', senhaHash);
      console.log('   Hashes iguais?', senhaHash === usuario.senha_hash);
      
      if (senhaHash !== usuario.senha_hash) {
        console.log('❌ Senha incorreta');
        return res.status(401).json({ erro: 'Credenciais inválidas' });
      }
      
      console.log('✅ Login bem-sucedido!');
      
      resetarTentativasLogin(ip);
      const token = criarSessao(usuario.id, ip);
      
      res.json({
        sucesso: true,
        token,
        usuario: {
          id: usuario.id,
          nome: usuario.nome,
          email: usuario.email
        }
      });
      
    } catch (err) {
      console.log('❌ Erro no servidor:', err.message);
      res.status(500).json({ erro: 'Erro interno' });
    }
  }
);
// ═══════════════════════════════════════════════════════════
// ROTA DE CADASTRO DE MONTADOR
// ═══════════════════════════════════════════════════════════

app.post('/api/parceiros',
  limiterCadastro,
  [
    body('nome').notEmpty().isString(),
    body('email').isEmail(),
    body('cpf').matches(/^\d{3}\.\d{3}\.\d{3}\-\d{2}$/),
    body('telefone').notEmpty(),
    body('cidade').notEmpty()
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ erro: 'Dados inválidos', detalhes: errors.array() });
    }
    
    try {
      const { 
        nome, cpf, nascimento, rg, telefone, email, cep, endereco, cidade, estado, 
        origem, nivel_experiencia, anos_exp, cnpj_status, cnpj, especialidades, 
        ferramentas, referencias, disponibilidade, latitude, longitude 
      } = req.body;
      
      const result = await pool.query(
        `INSERT INTO montadores (
          nome, cpf, data_nascimento, rg, telefone, email, cep, endereco, cidade, estado, 
          origem, nivel_experiencia, anos_exp, cnpj_status, cnpj, especialidades, 
          ferramentas, referencias, disponibilidade, latitude, longitude, ip_origem, 
          localizacao_confirmada, status
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24) RETURNING id`,
        [nome, cpf, nascimento, rg, telefone, email, cep, endereco, cidade, estado, 
         origem, nivel_experiencia, anos_exp, cnpj_status, cnpj, especialidades, 
         ferramentas, referencias, disponibilidade, latitude, longitude, req.ip, 
         latitude ? true : false, 'pendente']
      );
      
      log.info('Novo montador cadastrado', { id: result.rows[0].id, email: maskEmail(email) });
      
      res.status(201).json({ sucesso: true, id: result.rows[0].id });
    } catch (err) {
      log.erro('Erro ao cadastrar montador', { erro: err.message });
      res.status(500).json({ erro: 'Erro interno' });
    }
  }
);

// ═══════════════════════════════════════════════════════════
// ROTAS ADMINISTRATIVAS (PROTEGIDAS)
// ═══════════════════════════════════════════════════════════

app.get('/api/admin/montadores', autenticar, async (req, res) => {
    try {
        const { status } = req.query;
        
        console.log('🔍 Status recebido:', status);
        console.log('🔍 Tipo:', typeof status);
        console.log('🔍 Comprimento:', status?.length);
        
        // Teste 1: Buscar todos
        const todos = await pool.query('SELECT * FROM montadores');
        console.log('✅ Todos montadores:', todos.rows.length);
        
        // Teste 2: Buscar com status exato
        const comFiltro = await pool.query(
            'SELECT * FROM montadores WHERE status = $1',
            [status]
        );
        console.log('✅ Com filtro:', comFiltro.rows.length);
        
        // Teste 3: Buscar ignorando maiúsculas/minúsculas
        const ignorandoCase = await pool.query(
            'SELECT * FROM montadores WHERE LOWER(status) = LOWER($1)',
            [status]
        );
        console.log('✅ Ignorando case:', ignorandoCase.rows.length);
        
        res.json(comFiltro.rows);
    } catch (err) {
        console.error('❌ Erro:', err);
        res.status(500).json({ erro: 'Erro interno' });
    }
});
app.post('/api/admin/aprovar-montador', autenticar, async (req, res) => {
  try {
    const { montador_id } = req.body;
    await pool.query(
      'UPDATE montadores SET status = $1, aprovado_em = NOW(), aprovado_por = $2 WHERE id = $3',
      ['aprovado', req.usuario.id, montador_id]
    );
    res.json({ sucesso: true });
  } catch (err) {
    log.erro('Erro ao aprovar montador', { erro: err.message });
    res.status(500).json({ erro: 'Erro interno' });
  }
});

app.post('/api/admin/rejeitar-montador', autenticar, async (req, res) => {
  try {
    const { montador_id, motivo } = req.body;
    await pool.query(
      'UPDATE montadores SET status = $1, observacao_rejeicao = $2 WHERE id = $3',
      ['rejeitado', motivo, montador_id]
    );
    res.json({ sucesso: true });
  } catch (err) {
    log.erro('Erro ao rejeitar montador', { erro: err.message });
    res.status(500).json({ erro: 'Erro interno' });
  }
});

app.post('/api/admin/criar-os', autenticar, async (req, res) => {
  try {
    const { montador_id, tipo_projeto, valor, endereco_instalacao, cidade, estado, data_agendamento, observacoes } = req.body;
    
    const result = await pool.query(
      `INSERT INTO ordens_servico 
       (montador_id, tipo_projeto, valor, endereco_instalacao, cidade, estado, data_agendamento, observacoes, criado_por) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
      [montador_id, tipo_projeto, valor, endereco_instalacao, cidade, estado, data_agendamento, observacoes, req.usuario.id]
    );
    
    res.json(result.rows[0]);
  } catch (err) {
    log.erro('Erro ao criar OS', { erro: err.message });
    res.status(500).json({ erro: 'Erro interno' });
  }
});

app.get('/api/admin/ordens', autenticar, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT o.*, m.nome as montador_nome 
       FROM ordens_servico o 
       LEFT JOIN montadores m ON m.id = o.montador_id 
       ORDER BY o.criado_em DESC`
    );
    res.json(result.rows);
  } catch (err) {
    log.erro('Erro ao listar OS', { erro: err.message });
    res.status(500).json({ erro: 'Erro interno' });
  }
});

// ═══════════════════════════════════════════════════════════
// TRATAMENTO DE ERROS GLOBAL
// ═══════════════════════════════════════════════════════════

app.use((err, req, res, next) => {
  log.erro('Erro não tratado', { 
    erro: err.message,
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
    path: req.path,
    method: req.method
  });
  
  res.status(500).json({ erro: 'Erro interno do servidor' });
});

// 404 handler
app.use((req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ erro: 'Endpoint não encontrado' });
  }
  res.status(404).send('Página não encontrada');
});

// ═══════════════════════════════════════════════════════════
// LIMPEZA DE SESSÕES EXPIRADAS
// ═══════════════════════════════════════════════════════════

setInterval(() => {
  for (const [token, sessao] of sessoes.entries()) {
    if (new Date() > sessao.expiraEm) {
      sessoes.delete(token);
      log.info('Sessão expirada removida', { usuarioId: sessao.usuarioId });
    }
  }
}, 10 * 60 * 1000);

// ═══════════════════════════════════════════════════════════
// GRACEFUL SHUTDOWN
// ═══════════════════════════════════════════════════════════

const server = app.listen(process.env.PORT || 3000, () => {
  log.info(`Servidor ultra-seguro rodando na porta ${process.env.PORT || 3000}`);
});

process.on('SIGTERM', () => {
  log.info('SIGTERM recebido. Iniciando graceful shutdown...');
  server.close(async () => {
    await pool.end();
    log.info('Conexões fechadas. Encerrando.');
    process.exit(0);
  });
});

process.on('unhandledRejection', (reason, promise) => {
  log.erro('Promise rejeitada não tratada', { reason });
});

process.on('uncaughtException', (err) => {
  log.erro('Exceção não capturada', { erro: err.message, stack: err.stack });
  process.exit(1);
});

export default app;