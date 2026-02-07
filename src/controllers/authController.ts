import { Request, Response } from 'express';
import bcrypt from 'bcrypt';
import { prisma } from '../app';
import { generateTokens, verifyRefreshToken } from '../utils/jwt';
import { z } from 'zod';

const registerSchema = z.object({
    email: z.string().email(),
    password: z.string().min(8),
    name: z.string().optional()
});

const loginSchema = z.object({
    email: z.string().email(),
    password: z.string()
});

export const register = async (req: Request, res: Response) => {
    try {
        const validated = registerSchema.parse(req.body);
        const existing = await prisma.user.findUnique({ where: { email: validated.email } });
        if (existing) return res.status(400).json({ error: 'User already exists' });

        const hashedPassword = await bcrypt.hash(validated.password, 10);
        const user = await prisma.user.create({
            data: {
                email: validated.email,
                password: hashedPassword,
                name: validated.name || '',
                role: 'VIEWER' // Default role
            }
        });

        const { accessToken, refreshToken } = generateTokens(user);

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        });

        res.status(201).json({ accessToken, user: { id: user.id, email: user.email, role: user.role } });
    } catch (error: any) {
        res.status(400).json({ error: error.message || 'Registration failed' });
    }
};

export const login = async (req: Request, res: Response) => {
    try {
        const { email, password } = loginSchema.parse(req.body);
        const user = await prisma.user.findUnique({ where: { email } });

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const { accessToken, refreshToken } = generateTokens(user);

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        res.json({ accessToken, user: { id: user.id, email: user.email, role: user.role } });
    } catch (error: any) {
        res.status(400).json({ error: error.message || 'Login failed' });
    }
};
