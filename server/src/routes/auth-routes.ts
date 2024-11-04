import { Router, Request, Response } from 'express';
import { User } from '../models/user.js';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

// TODO: If the user exists and the password is correct, return a JWT token
export const login = async (req: Request, res: Response) => {
  const { username, password } = req.body;

  const user = await User.findOne({ 
    where: { username },
  });

  if(!user) {
    return res.status(404).json({ message: 'User not found' });
  }

  const validPassword = await bcrypt.compare(password, user.password);
  if(!validPassword) {
    return res.status(401).json({ message: 'Invalid password' });
  }

  const secretKey = process.env.JWT_SECRET_KEY || '';

  const token = jwt.sign({ username }, secretKey, { expiresIn: '5m' });

  return res.json({ token });

};

const router = Router();

// POST /login - Login a user
router.post('/login', login);

export default router;
