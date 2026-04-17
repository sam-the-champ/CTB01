import { Response } from 'express';

import * as TaskService from '../services/task.services';

export const create = async (req: any, res: Response) => {

  try {
    const { title, description } = req.body;
    // Extracts task data sent from frontend

    const task = await TaskService.createTask(
      req.user.userId,
      // Gets logged-in user's ID from JWT middleware

      title,
      description
    );
    // Calls service to insert task into database

    res.status(201).json(task);
    // Sends back created task with HTTP 201 (Created)

  } catch (error) {
    res.status(500).json({ error: "Failed to create task" });
  }
};


export const list = async (req: any, res: Response) => {

  try {
    const isAdmin = req.user.role === 'admin';

    const tasks = await TaskService.getUserTasks(
      req.user.userId,
      // Logged-in user's ID

      isAdmin
      
    );

    res.json(tasks);

  } catch (error) {
    res.status(500).json({ error: "Failed to fetch tasks" });
    
  }
};


export const updateStatus = async (req: any, res: Response) => {
  try {
    const taskId = req.params.id;
    const { status } = req.body;

    const isAdmin = req.user.role === 'admin';

    const updatedTask = await TaskService.updateTaskStatus(
      taskId,
      req.user.userId,
      status,
      isAdmin
    );

    if (!updatedTask) {
      return res.status(404).json({ error: "Task not found or not allowed" });
    }

    res.json(updatedTask);
  } catch (error) {
    res.status(500).json({ error: "Failed to update task" });
  }
};