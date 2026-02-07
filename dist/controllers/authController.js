"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.login = exports.register = void 0;
const bcrypt_1 = __importDefault(require("bcrypt"));
const app_1 = require("../app");
const jwt_1 = require("../utils/jwt");
const zod_1 = require("zod");
const registerSchema = zod_1.z.object({
    email: zod_1.z.string().email(),
    password: zod_1.z.string().min(8),
    name: zod_1.z.string().optional()
});
const loginSchema = zod_1.z.object({
    email: zod_1.z.string().email(),
    password: zod_1.z.string()
});
const register = async (req, res) => {
    try {
        const validated = registerSchema.parse(req.body);
        const existing = await app_1.prisma.user.findUnique({ where: { email: validated.email } });
        if (existing)
            return res.status(400).json({ error: 'User already exists' });
        const hashedPassword = await bcrypt_1.default.hash(validated.password, 10);
        const user = await app_1.prisma.user.create({
            data: {
                email: validated.email,
                password: hashedPassword,
                name: validated.name || '',
                role: 'VIEWER' // Default role
            }
        });
        const { accessToken, refreshToken } = (0, jwt_1.generateTokens)(user);
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        });
        res.status(201).json({ accessToken, user: { id: user.id, email: user.email, role: user.role } });
    }
    catch (error) {
        res.status(400).json({ error: error.message || 'Registration failed' });
    }
};
exports.register = register;
const login = async (req, res) => {
    try {
        const { email, password } = loginSchema.parse(req.body);
        const user = await app_1.prisma.user.findUnique({ where: { email } });
        if (!user || !(await bcrypt_1.default.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const { accessToken, refreshToken } = (0, jwt_1.generateTokens)(user);
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });
        res.json({ accessToken, user: { id: user.id, email: user.email, role: user.role } });
    }
    catch (error) {
        res.status(400).json({ error: error.message || 'Login failed' });
    }
};
exports.login = login;
