import jwt from 'jsonwebtoken';
/*
Imports the jsonwebtoken library.
Used to create (sign) and verify JWT tokens.
*/


export const generateAccessToken = (userId: string, role: string) => {
  return jwt.sign(
    { userId, role }, 
    /*
    Payload:
    Data stored inside the token.
    Here you're storing:
    - userId → identifies the user
    - role → used for authorization (admin/user)
    */

    process.env.JWT_ACCESS_SECRET!, 
    /*
    Secret key used to sign the token.
    This ensures the token cannot be tampered with.

    "!" = TypeScript non-null assertion
    (you're telling TS this value will exist)
    */

    { expiresIn: '15m' }
    /*
    Token expires in 15 minutes.

    Short lifespan = more secure
    If stolen, attacker has limited time to use it.
    */
  );
};

export const generateRefreshToken = (userId: string, familyId: string) => {
  return jwt.sign(
    { userId, familyId }, 
    /*
    Payload:
    - userId → identifies user
    - familyId → tracks token "family" for rotation security

    familyId is used to:
    - group tokens together
    - revoke all if one is compromised
    */

    process.env.JWT_REFRESH_SECRET!, 
    /*
    Different secret from access token.

    Best practice:
    - Separate secrets for access and refresh tokens
    */

    { expiresIn: '7d' }
    /*
    Token expires in 7 days.

    Long lifespan = allows user to stay logged in
    */
  );
};