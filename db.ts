import pg from 'pg';
import dotenv from 'dotenv';

dotenv.config();

const connectionString = process.env.DATABASE_URL;

if (!connectionString) {
  console.warn('⚠️ WARNING: DATABASE_URL environment variable is not set. Database connections will fail.');
}

// Alguns bancos (ex.: Postgres self-hosted no Easypanel) não têm SSL habilitado.
// Nesses casos o DATABASE_URL vem com ?sslmode=disable (ou defina DATABASE_SSL=false).
// Caso contrário, em produção usamos SSL sem verificar o certificado (hosts gerenciados).
const sslDisabled =
  /sslmode=disable/i.test(connectionString || '') ||
  process.env.DATABASE_SSL === 'false';

const pool = new pg.Pool({
  connectionString,
  ssl: sslDisabled
    ? false
    : process.env.NODE_ENV === 'production'
      ? { rejectUnauthorized: false }
      : undefined,
});

export default pool;

// Helper query function
export async function query(text: string, params?: any[]) {
  const start = Date.now();
  const res = await pool.query(text, params);
  const duration = Date.now() - start;
  if (process.env.NODE_ENV !== 'production') {
    console.log('⚡ [DB QUERY]', { text, duration: `${duration}ms`, rows: res.rowCount });
  } else {
    console.log('⚡ [DB QUERY]', { duration: `${duration}ms`, rows: res.rowCount });
  }
  return res;
}
