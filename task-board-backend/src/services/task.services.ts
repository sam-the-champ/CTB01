import { query } from '../config/db';


export const createTask = async (userId: string, title: string, description: string) => {

  const result = await query(
    'INSERT INTO tasks (user_id, title, description) VALUES ($1, $2, $3) RETURNING *',

    [userId, title, description]
    // Values passed into SQL placeholders (prevents SQL injection)
  );

  return result.rows[0];
};


export const getUserTasks = async (userId: string, isAdmin: boolean) => {
 
  if (isAdmin) {
    const result = await query(
      'SELECT * FROM tasks ORDER BY created_at DESC'
      
    );

    return result.rows;
    // Returns all tasks
  }

  const result = await query(
    'SELECT * FROM tasks WHERE user_id = $1 ORDER BY created_at DESC',
    [userId]
  
  );

  return result.rows;
 
};


export const updateTaskStatus = async (
  taskId: string,
  userId: string,
  status: string,
  isAdmin: boolean
) => {
 
  const sql = isAdmin 
    ? 'UPDATE tasks SET status = $1, updated_at = NOW() WHERE id = $2 RETURNING *'

    : 'UPDATE tasks SET status = $1, updated_at = NOW() WHERE id = $2 AND user_id = $3 RETURNING *';
   

  
  const params = isAdmin 
    ? [status, taskId]
    : [status, taskId, userId];



  const result = await query(sql, params);
  // Executes the SQL query

  return result.rows[0];
  
};