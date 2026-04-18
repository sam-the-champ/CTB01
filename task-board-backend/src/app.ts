import dns from "dns";
dns.setDefaultResultOrder("ipv4first");


import express, { Application } from 'express'; 
import helmet from 'helmet'; 
import cors from 'cors'; 
import cookieParser from 'cookie-parser'; 
import dotenv from 'dotenv'; 
import authRoutes from './routes/auth.routes';
import userRoutes from './routes/user.routes';
import taskRoutes from './routes/task.routes';


dotenv.config(); 

const app: Application = express(); 
// --- MIDDLEWARE ---

app.use(helmet()); // Adds security headers automatically (protects from XSS, clickjacking, etc.)
app.use(cors({
    origin: process.env.FRONTEND_URL, 
    credentials: true // Allows cookies (like refresh tokens) to be sent between frontend and backend
}));

// origin: process.env.FRONTEND_URL,    this is what the cos origin wibe when there is a frommtend project

app.get ("/", (req, res) => {
    res.send("API is running...");
});

app.use(express.json()); 
app.use(cookieParser()); 

app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/tasks', taskRoutes);


app.use((req, res) => {
    res.status(404).json({ error: "Endpoint not found"});
});


app.use((err: any, req:express.Request, res:express.Response, next:express.NextFunction) => {
    console.error("GLOBAL ERROR STACK:", err.stack);
    res.status(500).json({
        error: "Internal Server Error",
        message: err.message
    });
});


const PORT = process.env.PORT || 5000; 


app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    
});