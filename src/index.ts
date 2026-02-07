import dotenv from 'dotenv';
dotenv.config();

import app, { prisma } from './app';

const PORT = process.env.PORT || 5000;

async function main() {
    try {
        // Basic DB Connection Check
        await prisma.$connect();
        console.log('✅ Connected to Database');

        app.listen(PORT, () => {
            console.log(`🚀 Server running on http://localhost:${PORT}`);
        });
    } catch (error) {
        console.error('❌ Database connection failed:', error);
        process.exit(1);
    }
}

main();
