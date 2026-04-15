import express, { Application } from 'express'; // Import Express framework and its TypeScript type for the app instance
import helmet from 'helmet'; // Security middleware that adds HTTP headers to protect against attacks
import cors from 'cors'; // Enables Cross-Origin Resource Sharing (lets frontend talk to backend)
import cookieParser from 'cookie-parser'; // Parses cookies from incoming HTTP requests (needed for refresh tokens)
import dotenv from 'dotenv'; // Loads environment variables from a .env file into process.env
import authRoutes from './routes/auth.routes';

dotenv.config(); // Initializes dotenv so you can use process.env.PORT, process.env.FRONTEND_URL, etc.


const app: Application = express(); // Creates an Express application instance (your backend server)

// --- MIDDLEWARE ---

app.use(helmet()); // Adds security headers automatically (protects from XSS, clickjacking, etc.)
app.use(cors({
    origin: "*", // Only allow requests from your frontend URL (security control)   
    credentials: true // Allows cookies (like refresh tokens) to be sent between frontend and backend
}));
// origin: process.env.FRONTEND_URL,    this is what the cos origin wibe when there is a frommtend project
app.get ("/", (req, res) => {
    res.send("API is running...");
});

app.use(express.json()); // Allows server to read JSON data sent in request body (POST, PUT requests)
app.use(cookieParser()); // Enables reading cookies from requests (req.cookies)

app.use('/api/auth', authRoutes);

app.use((err: any, req:express.Request, res:express.Response, next:express.NextFunction) => {
    console.error("GLOBAL ERROR STACK:", err.stack);
    res.status(500).json({
        error: "Internal Server Error",
        message: err.message
    });
});

// Define the port number for the server
const PORT = process.env.PORT || 5000; 


app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    
});