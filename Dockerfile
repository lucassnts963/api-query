# Use uma imagem Node.js
FROM node:18

# Cria o diretório de trabalho
WORKDIR /app

# Copia o package.json e instala as dependências
COPY package*.json ./
RUN npm install && npm run migration:up

# Copia o restante do código
COPY . .

# Expõe a porta que o Fastify utiliza (3000)
EXPOSE 3000

# Comando para iniciar a aplicação
CMD ["npm", "start"]
