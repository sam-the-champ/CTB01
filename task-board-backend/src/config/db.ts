import { Pool } from 'pg';
import dotenv from 'dotenv';

dotenv.config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,

});


// A helper function to run queries and log them
export const query = (text: string, params?: any[]) => {

  return pool.query(text, params);
 
};


export default pool;
