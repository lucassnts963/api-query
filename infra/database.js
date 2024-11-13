import pg from "pg";

const { Client } = pg;

async function query(objectQuery) {
  let client;

  try {
    client = await getNewClient();
    const result = await client.query(objectQuery);
    return result;
  } catch (error) {
    console.error("Database query error:", error);
    throw error;
  } finally {
    if (client) {
      await client.end();
    }
  }
}

async function getNewClient() {
  const client = new Client({
    host: process.env.POSTGRES_HOST,
    port: process.env.POSTGRES_PORT,
    user: process.env.POSTGRES_USER,
    database: process.env.POSTGRES_DB,
    password: process.env.POSTGRES_PASSWORD,
    ssl: getSSLconfig(),
  });

  try {
    await client.connect();
  } catch (error) {
    console.error("Failed to connect to the database:", error);
    throw error;
  }

  return client;
}

function getSSLconfig() {
  return true;
  if (process.env.POSTGRES_CA) {
    return {
      ca: process.env.POSTGRES_CA,
    };
  }

  return process.env.NODE_ENV === "production" ? true : false;
}

export default {
  getNewClient,
  query,
};
