# API de Usuários e Perfis

Este projeto é uma API REST desenvolvida em Node.js com Express e Prisma, focada na gestão de usuários e seus perfis por meio de um relacionamento um-para-muitos (1:N) em banco PostgreSQL.

A aplicação serve como base para estudos de autenticação com JWT, segurança de senha com Argon2, persistência com Prisma e organização de endpoints REST.

---

## 🏗️ Arquitetura do projeto

A API segue o modelo cliente/servidor, com middlewares de monitoramento e validação antes de alcançar as regras de negócio:

* **Express:** gerencia os endpoints e rotas da aplicação.
* **Prisma ORM:** abstrai a interação com as tabelas `Usuario` e `Perfil`. Um usuário pode ter vários perfis.
* **Morgan:** registra requisições no terminal em tempo real.

---

## 🛠️ Tecnologias utilizadas

* **Runtime:** Node.js
* **Linguagem:** JavaScript
* **Framework web:** Express
* **Banco de dados:** PostgreSQL
* **ORM:** Prisma Client
* **Autenticação:** JWT + Argon2

---

## 🚀 Como configurar e executar

### 1. Instalar as dependências

No terminal, rode:

```bash
npm install
```

### 2. Configurar as variáveis de ambiente

Crie um arquivo `.env` com a URL do banco e as chaves JWT:

```bash
DATABASE_URL=postgresql://usuario:senha@localhost:5432/seu_banco
ACCESS_TOKEN_SECRET=sua_chave_acesso
REFRESH_TOKEN_SECRET=sua_chave_refresh
```

### 3. Iniciar a aplicação

```bash
npm run dev
```

---

## 🔐 Observação sobre o Argon2

O Argon2 gera hashes com parâmetros específicos, como:

* `argon2id` como algoritmo principal
* `m=65536,t=3,p=4` como configuração de custo
* salt e hash únicos para cada senha

Esses elementos garantem maior resistência contra ataques de força bruta e rainbow tables.