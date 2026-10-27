import mysql, { type Pool } from "mysql2/promise";

let pool: Pool | undefined;

export function getPool(): Pool {
  if (pool) return pool;

  const required = ["MYSQL_HOST", "MYSQL_USER", "MYSQL_DATABASE"] as const;
  const missing = required.filter((name) => !process.env[name]);
  if (missing.length > 0) {
    throw new Error(`Missing database configuration: ${missing.join(", ")}`);
  }

  pool = mysql.createPool({
    host: process.env.MYSQL_HOST,
    port: Number(process.env.MYSQL_PORT ?? 3306),
    user: process.env.MYSQL_USER,
    password: process.env.MYSQL_PASSWORD ?? "",
    database: process.env.MYSQL_DATABASE,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    dateStrings: true,
  });

  return pool;
}
