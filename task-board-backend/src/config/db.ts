import { Pool } from 'pg';
/*
Imports the Pool class from the 'pg' (node-postgres) library.
Pool is used to manage multiple database connections efficiently.
Instead of opening a new connection every time, it reuses existing ones.
*/

import dotenv from 'dotenv';
/*
Imports dotenv so we can load environment variables from a .env file.
This helps keep sensitive info like database URLs out of code.
*/

dotenv.config();
/*
Loads variables from .env into process.env
Example: DATABASE_URL becomes available here
*/


// The "Pool" manages multiple connections to the database. 
// Think of it as a team of workers waiting to handle queries.
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  /*
  Creates a connection pool to PostgreSQL.

  connectionString:
  - This is your database URL stored in .env
  - Example: postgres://user:password@localhost:5432/mydb

  The pool automatically:
  - Opens connections when needed
  - Reuses existing connections
  - Handles multiple users at the same time efficiently
  */
});


// A helper function to run queries and log them
export const query = (text: string, params?: any[]) => {
  /*
  This is a reusable function for running SQL queries.

  text:
  - The SQL query string (e.g. "SELECT * FROM users")

  params:
  - Optional values to safely insert into the query
  - Prevents SQL injection (VERY IMPORTANT for security)
  */

  return pool.query(text, params);
  /*
  Executes the SQL query using the connection pool.
  Returns a Promise with the result of the query.
  */
};


export default pool;
/*
Exports the pool so it can be used directly in other files
Example: for advanced database operations or transactions
*/