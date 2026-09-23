import express from "express";
import cors from "cors";
import { prisma } from "./lib/prisma.ts";
import morgan from "morgan";
import argon2 from "argon2";
import jwt from "jsonwebtoken";
import { verificarToken } from "./middleware/authMiddleware.js";

// 🔐 Secrets separadas para acesso e renovação de sessão
const ACCESS_SECRET = process.env.ACCESS_TOKEN_SECRET || "access_secret_default";
const REFRESH_SECRET = process.env.REFRESH_TOKEN_SECRET || "refresh_secret_default";

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(cors());
app.use(morgan("dev"));

app.use((req, res, next) => {
    console.log(`\n------------------------------`);
    next();
});

// =========================================================================
// 🔓 ROTAS PÚBLICAS
// =========================================================================

// 📥 1. Cadastro de usuários
app.post("/usuarios", async (req, res) => {
    console.log(`📥 [API] Recebendo dados para cadastrar um novo usuário...`);
    try {
        const { email, senha, nome, bio, fotoUrl } = req.body;
        
        // 🛡️ Segurança: Gerando hash Argon2id antes de salvar no banco
        const senhaHash = await argon2.hash(senha, { type: argon2.argon2id });
        
        const novoUsuario = await prisma.usuario.create({
            data: {
                email,
                senha: senhaHash,
                nome,
                perfis: {
                    create: { bio, fotoUrl }
                }
            },
            include: { perfis: true }
        });
        
        console.log(`✅ [API] Usuário criado com sucesso! ID: ${novoUsuario.id}`);
        res.status(201).json(novoUsuario); 
    } catch (error) {
        console.error("❌ [API Erro] Erro completo do Prisma:", error.message || error);
        res.status(400).json({ erro: "Erro ao criar usuario", detalhe: error.message || error });
    }
});

// 📥 2. Login com geração de access e refresh token
app.post('/login', async (req, res) => {
//   try {
    const { email, senha } = req.body;
    
    const usuario = await prisma.usuario.findUnique({ where: { email } });
    if (!usuario) return res.status(401).json({ erro: "Credenciais inválidas." });

    const senhaCorreta = await argon2.verify(usuario.senha, senha);
    if (!senhaCorreta) return res.status(401).json({ erro: "Credenciais inválidas." });

    const payload = { id: usuario.id, email: usuario.email };

    // Access token de curta duração e refresh token de longa duração
    const accessToken = jwt.sign(payload, ACCESS_SECRET, { expiresIn: '15m' });
    const refreshToken = jwt.sign(payload, REFRESH_SECRET, { expiresIn: '30d' });

    // Armazena o refresh token para validação posterior
    await prisma.usuario.update({
      where: { id: usuario.id },
      data: { refreshToken: refreshToken }
    });

    return res.json({
      accessToken,
      refreshToken,
      usuario: { id: usuario.id, email: usuario.email }
    });

//   } catch (error) {
//     return res.status(500).json({ erro: "Erro no login" });
//   }
});

// 🔄 3. Renovação de sessão
app.post('/refresh', async (req, res) => {
  try {
    const { tokenDeRenovacao } = req.body; 

    if (!tokenDeRenovacao) {
      return res.status(401).json({ erro: "Refresh Token não fornecido." });
    }

    // 1. Valida a assinatura e a expiração do refresh token
    const dadosVerificados = jwt.verify(tokenDeRenovacao, REFRESH_SECRET);

    // 2. Busca o usuário para confirmar a sessão ativa
    const usuario = await prisma.usuario.findUnique({
      where: { id: dadosVerificados.id }
    });

    if (!usuario || usuario.refreshToken !== tokenDeRenovacao) {
      return res.status(403).json({ erro: "Refresh token inválido ou revogado." });
    }

    // 3. Gera um novo access token de curta duração
    const novoPayload = { id: usuario.id, email: usuario.email };
    const novoAccessToken = jwt.sign(novoPayload, ACCESS_SECRET, { expiresIn: '15m' });

    console.log(`✅ [API] Sessão renovada com sucesso para o usuário: ${usuario.email}`);

    return res.json({ accessToken: novoAccessToken });

  } catch (error) {
    return res.status(403).json({ erro: "Sessão expirada. Faça login novamente." });
  }
});


// =========================================================================
// 🔒 ROTAS PROTEGIDAS (Exigem Access Token válido no Header)
// =========================================================================

app.get("/usuarios", verificarToken, async (req, res) => {
    console.log(`🔍 [API] Buscando todos os usuários no banco de dados...`);
    try {
        console.log(`🔑 ID do Usuário requisitante: ${req.usuarioLogadoId}`);
        const usuarios = await prisma.usuario.findMany({ include: { perfis: true } });
        res.json(usuarios);
    } catch (error) {
        res.status(500).json({ error: "Erro ao buscar usuarios" });
    }
});

app.put("/usuarios/:id", verificarToken, async (req, res) => {
    const { id } = req.params;
    try {
        const { email, senha, bio, fotoUrl } = req.body;
        
        const senhaHash = senha ? await argon2.hash(senha, { type: argon2.argon2id }) : undefined;

        const usuarioAtualizado = await prisma.usuario.update({
            where: { id: Number(id) },
            data: {
                email,
                senha: senhaHash,
                perfis: (bio !== undefined || fotoUrl !== undefined)
                    ? { create: { bio, fotoUrl } }
                    : undefined
            },
            include: { perfis: true }
        });
        res.json(usuarioAtualizado);
    } catch (error) {
        res.status(400).json({ erro: "Erro ao atualizar usuario", detalhe: error.message });
    }
});

app.patch("/usuarios/:id", verificarToken, async (req, res) => {
    const { id } = req.params;
    try {
        const { email, senha, bio, fotoUrl } = req.body;
        const senhaHash = senha ? await argon2.hash(senha, { type: argon2.argon2id }) : undefined;

        const dadosAtualizacao = {
            email,
            senha: senhaHash,
            perfis: (bio !== undefined || fotoUrl !== undefined)
                ? { create: { bio, fotoUrl } }
                : undefined
        };

        Object.keys(dadosAtualizacao).forEach(key => dadosAtualizacao[key] === undefined && delete dadosAtualizacao[key]);

        const usuario = await prisma.usuario.update({
            where: { id: Number(id) },
            data: dadosAtualizacao,
            include: { perfis: true }
        });
        res.json(usuario);
    } catch (error) {
        res.status(400).json({ erro: "Erro ao atualizar parcialmente", detalhe: error.message });
    }
});

app.post("/usuarios/:id/perfis", verificarToken, async (req, res) => {
    const { id } = req.params;
    const { bio, fotoUrl } = req.body;

    try {
        const perfil = await prisma.perfil.create({
            data: {
                bio,
                fotoUrl,
                usuario: { connect: { id: Number(id) } }
            }
        });
        res.status(201).json(perfil);
    } catch (error) {
        res.status(400).json({ erro: "Erro ao criar perfil", detalhe: error.message });
    }
});

app.get("/usuarios/:id/perfis", verificarToken, async (req, res) => {
    try {
        const perfis = await prisma.perfil.findMany({
            where: { usuarioId: Number(req.params.id) }
        });
        res.json(perfis);
    } catch (error) {
        res.status(500).json({ erro: "Erro ao buscar perfis", detalhe: error.message });
    }
});

app.put("/usuarios/:id/perfis/:perfilId", verificarToken, async (req, res) => {
    const { id, perfilId } = req.params;
    const { bio, fotoUrl } = req.body;

    try {
        const resultado = await prisma.perfil.updateMany({
            where: { id: Number(perfilId), usuarioId: Number(id) },
            data: { bio, fotoUrl }
        });

        if (resultado.count === 0) {
            return res.status(404).json({ erro: "Perfil não encontrado para este usuario" });
        }

        const perfilAtualizado = await prisma.perfil.findUnique({
            where: { id: Number(perfilId) }
        });
        res.json(perfilAtualizado);
    } catch (error) {
        res.status(400).json({ erro: "Erro ao atualizar perfil", detalhe: error.message });
    }
});

app.delete("/usuarios/:id", verificarToken, async (req, res) => {
    const { id } = req.params;
    try {
        await prisma.usuario.delete({ where: { id: Number(id) } });
        res.status(204).send();
    } catch (error) {
        res.status(400).json({ erro: "Erro ao deletar usuario", detalhe: error.message });
    }
});

app.listen(PORT, () => {
    console.log(`✅ API de usuários e perfis rodando em: http://localhost:${PORT}`);
});