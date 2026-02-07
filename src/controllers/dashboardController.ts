import { Request, Response } from 'express';
import { prisma } from '../app';

export const getDashboardStats = async (req: Request, res: Response) => {
    try {
        const [totalEvents, totalAlerts, policies] = await Promise.all([
            prisma.event.count(),
            prisma.alert.count({ where: { status: 'OPEN' } }),
            prisma.policy.count({ where: { isActive: true } }),
        ]);

        // Get recent events
        const recentEvents = await prisma.event.findMany({
            orderBy: { timestamp: 'desc' },
            take: 10,
            select: {
                id: true,
                type: true,
                source: true,
                riskScore: true,
                status: true,
                timestamp: true,
            },
        });

        // Get active sources (agents)
        const events = await prisma.event.findMany({
            select: { source: true },
            distinct: ['source'],
        });
        const activeSources = events.length;

        // Get event counts by 10-minute interval (last 4 hours for demo clarity)
        const fourHoursAgo = new Date(Date.now() - 4 * 60 * 60 * 1000);

        // Fetch timestamps
        const recentActivity = await prisma.event.findMany({
            where: { timestamp: { gt: fourHoursAgo } },
            select: { timestamp: true }
        });

        // Group by 10-minute intervals
        const intervalMap = new Map<string, number>();

        // Pre-fill last 4 hours with 0 to ensure continuity
        for (let i = 0; i < 24; i++) {
            const date = new Date(Date.now() - i * 10 * 60 * 1000);
            date.setSeconds(0, 0);
            date.setMinutes(Math.floor(date.getMinutes() / 10) * 10);
            intervalMap.set(date.toISOString(), 0);
        }

        recentActivity.forEach((e: { timestamp: Date }) => {
            const date = new Date(e.timestamp);
            date.setSeconds(0, 0);
            date.setMinutes(Math.floor(date.getMinutes() / 10) * 10);
            const key = date.toISOString();
            if (intervalMap.has(key)) {
                intervalMap.set(key, (intervalMap.get(key) || 0) + 1);
            }
        });

        const eventsByHour = Array.from(intervalMap.entries())
            .map(([hour, count]) => ({ hour, count }))
            .sort((a, b) => new Date(a.hour).getTime() - new Date(b.hour).getTime());

        res.json({
            stats: {
                totalEvents,
                activeAlerts: totalAlerts,
                activeSources,
                activePolicies: policies,
            },
            recentEvents,
            eventsByHour,
        });
    } catch (error: any) {
        console.error('Dashboard stats error:', error);
        res.status(500).json({ error: 'Failed to fetch dashboard stats' });
    }
};
