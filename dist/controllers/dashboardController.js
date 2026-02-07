"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getDashboardStats = void 0;
const app_1 = require("../app");
const getDashboardStats = async (req, res) => {
    try {
        const [totalEvents, totalAlerts, policies] = await Promise.all([
            app_1.prisma.event.count(),
            app_1.prisma.alert.count({ where: { status: 'OPEN' } }),
            app_1.prisma.policy.count({ where: { isActive: true } }),
        ]);
        // Get recent events
        const recentEvents = await app_1.prisma.event.findMany({
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
        const events = await app_1.prisma.event.findMany({
            select: { source: true },
            distinct: ['source'],
        });
        const activeSources = events.length;
        // Get event counts by 10-minute interval (last 4 hours for demo clarity)
        const fourHoursAgo = new Date(Date.now() - 4 * 60 * 60 * 1000);
        // Fetch timestamps
        const recentActivity = await app_1.prisma.event.findMany({
            where: { timestamp: { gt: fourHoursAgo } },
            select: { timestamp: true }
        });
        // Group by 10-minute intervals
        const intervalMap = new Map();
        // Pre-fill last 4 hours with 0 to ensure continuity
        for (let i = 0; i < 24; i++) {
            const date = new Date(Date.now() - i * 10 * 60 * 1000);
            date.setSeconds(0, 0);
            date.setMinutes(Math.floor(date.getMinutes() / 10) * 10);
            intervalMap.set(date.toISOString(), 0);
        }
        recentActivity.forEach((e) => {
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
    }
    catch (error) {
        console.error('Dashboard stats error:', error);
        res.status(500).json({ error: 'Failed to fetch dashboard stats' });
    }
};
exports.getDashboardStats = getDashboardStats;
