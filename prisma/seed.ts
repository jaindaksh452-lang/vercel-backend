import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';

const prisma = new PrismaClient();

async function main() {
    console.log('🌱 Seeding database...');

    // Create Admin User
    const adminPassword = await bcrypt.hash('Admin123!', 10);
    const admin = await prisma.user.upsert({
        where: { email: 'admin@cortex.com' },
        update: {
            password: adminPassword,
        },
        create: {
            email: 'admin@cortex.com',
            password: adminPassword,
            name: 'Admin User',
            role: 'ADMIN',
        },
    });
    console.log('✅ Created admin user:', admin.email);

    // Create Demo Analyst
    const analystPassword = await bcrypt.hash('Analyst123!', 10);
    const analyst = await prisma.user.upsert({
        where: { email: 'analyst@cortex.com' },
        update: {
            password: analystPassword,
        },
        create: {
            email: 'analyst@cortex.com',
            password: analystPassword,
            name: 'Security Analyst',
            role: 'ANALYST',
        },
    });
    console.log('✅ Created analyst user:', analyst.email);

    // Create Default Policies with MITRE Mapping
    const policies = [
        {
            name: 'Detect PowerShell Execution',
            rule: {
                field: 'process',
                operator: 'equals',
                value: 'powershell.exe',
            },
            isActive: true,
            mitreTactic: 'Execution',
            mitreTechniqueId: 'T1059',
            mitreTechniqueName: 'Command and Scripting Interpreter',
        },
        {
            name: 'Suspicious Network Connection',
            rule: {
                field: 'dest_ip',
                operator: 'contains',
                value: '45.33',
            },
            isActive: true,
            mitreTactic: 'Command and Control',
            mitreTechniqueId: 'T1071',
            mitreTechniqueName: 'Application Layer Protocol',
        },
        {
            name: 'Passwd File Access',
            rule: {
                field: 'file',
                operator: 'contains',
                value: '/etc/passwd',
            },
            isActive: true,
            mitreTactic: 'Credential Access',
            mitreTechniqueId: 'T1003',
            mitreTechniqueName: 'OS Credential Dumping',
        },
        {
            name: 'Detect PsExec Usage',
            rule: {
                field: 'process',
                operator: 'equals',
                value: 'psexec.exe',
            },
            isActive: true,
            mitreTactic: 'Lateral Movement',
            mitreTechniqueId: 'T1570',
            mitreTechniqueName: 'Lateral Tool Transfer',
        },
        {
            name: 'Sensitive File Access (Shadow)',
            rule: {
                field: 'command',
                operator: 'contains',
                value: '/etc/shadow',
            },
            isActive: true,
            mitreTactic: 'Credential Access',
            mitreTechniqueId: 'T1003',
            mitreTechniqueName: 'OS Credential Dumping',
        },
        {
            name: 'SSH Auth Failure Spike',
            rule: {
                field: 'type',
                operator: 'equals',
                value: 'AUTH_FAILURE',
            },
            isActive: true,
            mitreTactic: 'Credential Access',
            mitreTechniqueId: 'T1110',
            mitreTechniqueName: 'Brute Force',
        },
    ];

    for (const policy of policies) {
        await prisma.policy.upsert({
            where: { name: policy.name },
            update: {},
            create: policy,
        });
        console.log('✅ Created policy:', policy.name);
    }

    console.log('✅ Seeding complete!');
}

main()
    .catch((e) => {
        console.error('❌ Seeding failed:', e);
        process.exit(1);
    })
    .finally(async () => {
        await prisma.$disconnect();
    });
