-- ============================================================
-- NF MÓVEIS - SCHEMA DO BANCO DE DADOS (VERSÃO COMPLETA)
-- ============================================================

-- Extensões necessárias
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================
-- TABELA DE ADMINISTRADORES
-- ============================================================
CREATE TABLE IF NOT EXISTS admins (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    nome VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    senha_hash VARCHAR(64) NOT NULL,
    criado_em TIMESTAMP DEFAULT NOW(),
    ultimo_acesso TIMESTAMP,
    ativo BOOLEAN DEFAULT TRUE
);

-- ============================================================
-- TABELA DE MONTADORES (CADASTRO COMPLETO)
-- ============================================================
CREATE TABLE IF NOT EXISTS montadores (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Dados Pessoais
    nome VARCHAR(100) NOT NULL,
    cpf VARCHAR(14) UNIQUE NOT NULL,
    rg VARCHAR(20),
    data_nascimento DATE NOT NULL,
    telefone VARCHAR(20) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    
    -- Endereço
    cep VARCHAR(9) NOT NULL,
    endereco TEXT NOT NULL,
    cidade VARCHAR(50) NOT NULL,
    estado VARCHAR(2) NOT NULL DEFAULT 'GO',
    latitude DECIMAL(10,8),
    longitude DECIMAL(11,8),
    
    -- Geolocalização
    ip_origem VARCHAR(45),
    localizacao_confirmada BOOLEAN DEFAULT FALSE,
    
    -- Experiência
    nivel_experiencia VARCHAR(20) CHECK (nivel_experiencia IN ('simples', 'medio_complexo', 'luxo')),
    anos_exp VARCHAR(20),
    cnpj_status VARCHAR(10) CHECK (cnpj_status IN ('nao', 'sim')),
    cnpj VARCHAR(18),
    especialidades TEXT[],
    ferramentas TEXT,
    referencias TEXT,
    disponibilidade TEXT,
    
    -- Origem
    origem VARCHAR(50),
    
    -- Status
    status VARCHAR(20) DEFAULT 'pendente' CHECK (status IN ('pendente', 'aprovado', 'rejeitado')),
    observacao_rejeicao TEXT,
    
    -- Documentos (armazenar apenas caminhos/ids)
    doc_rg VARCHAR(255),
    doc_cpf VARCHAR(255),
    doc_comprovante VARCHAR(255),
    doc_foto VARCHAR(255),
    doc_antecedente VARCHAR(255),
    doc_portfolio TEXT[],
    
    -- Controle
    criado_em TIMESTAMP DEFAULT NOW(),
    aprovado_em TIMESTAMP,
    aprovado_por UUID REFERENCES admins(id),
    
    -- Metadados
    metadata JSONB DEFAULT '{}'::jsonb
);

-- ============================================================
-- ÍNDICES PARA PERFORMANCE
-- ============================================================
CREATE INDEX idx_montadores_status ON montadores(status);
CREATE INDEX idx_montadores_cidade ON montadores(cidade);
CREATE INDEX idx_montadores_estado ON montadores(estado);
CREATE INDEX idx_montadores_criado_em ON montadores(criado_em);
CREATE INDEX idx_montadores_email ON montadores(email);
CREATE INDEX idx_montadores_cpf ON montadores(cpf);

-- ============================================================
-- TABELA DE ORDENS DE SERVIÇO (OS)
-- ============================================================
CREATE TABLE IF NOT EXISTS ordens_servico (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    numero_os VARCHAR(20) UNIQUE NOT NULL,
    montador_id UUID REFERENCES montadores(id),
    tipo_projeto VARCHAR(30) CHECK (tipo_projeto IN ('simples', 'medio', 'complexo', 'luxo')),
    valor DECIMAL(10,2) NOT NULL,
    endereco_instalacao TEXT NOT NULL,
    cidade VARCHAR(50) NOT NULL,
    estado VARCHAR(2) NOT NULL,
    latitude DECIMAL(10,8),
    longitude DECIMAL(11,8),
    data_agendamento DATE NOT NULL,
    data_conclusao DATE,
    status VARCHAR(20) DEFAULT 'agendada' CHECK (status IN ('agendada', 'em_andamento', 'concluida', 'cancelada')),
    observacoes TEXT,
    
    -- Controle de criação
    criado_por UUID REFERENCES admins(id),
    criado_em TIMESTAMP DEFAULT NOW()
);

-- ============================================================
-- TABELA DE HISTÓRICO DE EVENTOS
-- ============================================================
CREATE TABLE IF NOT EXISTS historico_eventos (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entidade_tipo VARCHAR(30) NOT NULL, -- 'montador', 'os', 'admin'
    entidade_id UUID NOT NULL,
    acao VARCHAR(50) NOT NULL,
    dados_anteriores JSONB,
    dados_novos JSONB,
    ip_origem VARCHAR(45),
    realizado_por UUID REFERENCES admins(id),
    realizado_em TIMESTAMP DEFAULT NOW()
);

-- ============================================================
-- TRIGGER PARA GERAR NÚMERO DA OS AUTOMATICAMENTE
-- ============================================================
CREATE OR REPLACE FUNCTION gerar_numero_os()
RETURNS TRIGGER AS $$
DECLARE
    ano TEXT := to_char(NOW(), 'YYYY');
    sequencial INTEGER;
BEGIN
    SELECT COALESCE(MAX(CAST(SUBSTRING(numero_os FROM 5) AS INTEGER)), 0) + 1
    INTO sequencial
    FROM ordens_servico
    WHERE SUBSTRING(numero_os FROM 1 FOR 4) = ano;
    
    NEW.numero_os := ano || '-' || LPAD(sequencial::TEXT, 5, '0');
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_gerar_numero_os
    BEFORE INSERT ON ordens_servico
    FOR EACH ROW
    EXECUTE FUNCTION gerar_numero_os();

-- ============================================================
-- INSERIR ADMIN PADRÃO (SENHA: Admin@123)
-- ============================================================
-- A senha já deve estar com HMAC+SHA256, mas por enquanto inserimos um placeholder
-- O script criar-admin.js vai substituir por uma senha real com hash
INSERT INTO admins (nome, email, senha_hash)
VALUES ('Administrador', 'admin@nfmoveis.com.br', 'PLACEHOLDER')
ON CONFLICT (email) DO NOTHING;

-- ============================================================
-- GRANT PERMISSIONS (SE NECESSÁRIO)
-- ============================================================
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO postgres;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO postgres;

-- ============================================================
-- FIM DO SCRIPT
-- ============================================================
