// Adicione às dependências:
// npm install @fastify/jwt bcrypt
import path from "node:path";

import Fastify from "fastify";
import cors from "@fastify/cors";
import fjwt from "@fastify/jwt";
import fastifyStatic from "@fastify/static";
import pg from "pg";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import { fileURLToPath } from "url";

import database from "./infra/database.js";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const fastify = Fastify({
  logger: true,
});

// Configuração do CORS
await fastify.register(cors, {
  origin: true,
});

// Configuração do plugin de arquivos estáticos
await fastify.register(fastifyStatic, {
  root: path.join(__dirname, "public"), // Define o diretório "public" para arquivos estáticos
  prefix: "/", // Os arquivos serão servidos na raiz, ex: /register.html
});

// Configuração do JWT
await fastify.register(fjwt, {
  secret: process.env.JWT_SECRET,
});

// Middleware para verificar conexão com banco
fastify.addHook("onRequest", async (request, reply) => {
  try {
    request.client = await database.getNewClient();
  } catch (err) {
    reply.code(500).send({ error: "Erro ao conectar ao banco de dados" });
  }
});

// Middleware para liberar conexão após a requisição
fastify.addHook("onResponse", async (request) => {
  if (request.client) {
    await request.client.end();
  }
});

// Middleware de autenticação
const authenticate = async (request, reply) => {
  try {
    await request.jwtVerify();
  } catch (err) {
    reply.code(401).send({ error: "Não autorizado" });
  }
};

// Rota de registro de usuário
fastify.post("/auth/register", async (request, reply) => {
  const { email, password, name } = request.body;

  try {
    // Verifica se usuário já existe
    const userExists = await database.query({
      text: "SELECT * FROM users WHERE email = $1",
      values: [email],
    });

    if (userExists.rows.length > 0) {
      return reply.code(400).send({ error: "Email já cadastrado" });
    }

    // Hash da senha
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insere novo usuário
    const result = await database.query({
      text: "INSERT INTO users (email, password, name) VALUES ($1, $2, $3) RETURNING uuid, email, name",
      values: [email, hashedPassword, name],
    });

    // Gera token JWT
    const token = fastify.jwt.sign({
      id: result.rows[0].id,
      email: result.rows[0].email,
    });

    return {
      user: result.rows[0],
      token,
    };
  } catch (err) {
    reply.code(400).send({
      error: "Erro ao registrar usuário",
      details: err.message,
    });
  }
});

// Rota de login
fastify.post("/auth/login", async (request, reply) => {
  const { email, password } = request.body;

  try {
    // Busca usuário
    const result = await database.query({
      text: "SELECT * FROM users WHERE email = $1",
      values: [email],
    });

    if (result.rows.length === 0) {
      return reply.code(401).send({ error: "Credenciais inválidas" });
    }

    const user = result.rows[0];

    // Verifica senha
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return reply.code(401).send({ error: "Credenciais inválidas" });
    }

    // Gera token JWT
    const token = fastify.jwt.sign({
      id: user.id,
      email: user.email,
    });

    return {
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
      },
      token,
    };
  } catch (err) {
    reply.code(400).send({
      error: "Erro ao fazer login",
      details: err.message,
    });
  }
});

// Rota protegida para executar queries SELECT
fastify.post(
  "/query/select",
  { onRequest: [authenticate] },
  async (request, reply) => {
    const { query, params } = request.body;

    try {
      const result = await database.query({ text: query, values: params });
      return { data: result.rows };
    } catch (err) {
      reply.code(400).send({
        error: "Erro ao executar query",
        details: err.message,
      });
    }
  }
);

// Rota protegida para executar mutations
fastify.post(
  "/query/mutation",
  { onRequest: [authenticate] },
  async (request, reply) => {
    const { query, params } = request.body;

    try {
      await database.query("BEGIN");
      const result = await database.query({
        text: query,
        values: params,
      });
      await database.query("COMMIT");

      return {
        success: true,
        rowCount: result.rowCount,
        data: result.rows,
      };
    } catch (err) {
      await database.query("ROLLBACK");
      reply.code(400).send({
        error: "Erro ao executar mutation",
        details: err.message,
      });
    }
  }
);

// Rota para verificar token (útil para o frontend)
fastify.get("/auth/verify", { onRequest: [authenticate] }, async (request) => {
  return {
    user: request.user,
    valid: true,
  };
});

try {
  await fastify.listen({ port: process.env.PORT || 3000 });
  console.log(`Servidor rodando na porta ${fastify.server.address().port}`);
} catch (err) {
  fastify.log.error(err);
  process.exit(1);
}
