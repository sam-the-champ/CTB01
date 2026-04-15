import { z } from 'zod';
/*
Imports Zod library.
Zod is used to validate incoming data (like request bodies in APIs).
It ensures users send correct and safe data.
*/


export const RegisterSchema = z.object({
/*
Creates a validation schema called RegisterSchema.
This defines the exact structure of data allowed during user registration.
*/

  email: z.string().email("Invalid email format"),
  /*
  email field rules:
  - Must be a string
  - Must follow valid email format (example: user@gmail.com)
  - If invalid → returns error message: "Invalid email format"
  */

  password: z.string().min(8, "Password must be at least 8 characters"),
  /*
  password field rules:
  - Must be a string
  - Must be at least 8 characters long
  - If too short → returns error message
  */

  role: z.enum(['user', 'admin']).optional(),
  /*
  role field rules:
  - Must be either 'user' or 'admin'
  - .optional() means user does NOT have to send it
    (default role can be assigned automatically in backend)
  */
});