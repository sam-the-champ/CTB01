import { query } from '../config/db';


export const logAction = async (
  userId: string,
  action: string,
  entityType: string,
  entityId?: string,
  metadata?: any
) => {


  try {
    await query(
      `INSERT INTO audit_logs (user_id, action, entity_type, entity_id, metadata) 
       VALUES ($1, $2, $3, $4, $5)`,
      
      [
        userId,
        action,
        entityType,
        entityId,
        JSON.stringify(metadata)
        // Converts metadata object into JSON string before saving to DB
      ]
    );

  } catch (error) {
    // If logging fails, catch error so app does not crash

    console.error("CRITICAL: Failed to write audit log", error);
   
  }
};