// This middleware:

// Protects your backend routes.

// Checks for a JWT in cookies or headers.

// Validates it using your secret key.

// Attaches user info to the request if valid.

// Throws an error if the token is missing or invalid.



import {UnauthorizedException}  from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Request, Response, NextFunction } from 'express';
import { verify } from 'jsonwebtoken';  
import * as dotenv from 'dotenv';
dotenv.config();

export function AuthenticationMiddleware(req: Request, res: Response, next: NextFunction) {
  const token = req.cookies?.token || req.headers.authorization?.split(' ')[1];
  if (!token) {
    throw new UnauthorizedException('No token provided');
  }
  try{
    const decoded: any = verify(token, String(process.env.JWT_SECRET));
    req['user']= decoded.user;
    next();
  }catch(err)
    {
        throw new UnauthorizedException('Invalid token');
    }
}