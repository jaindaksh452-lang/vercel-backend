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
        // Get event counts by hour (last 24 hours) - Safe JS implementation
        const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
        // Fetch only timestamps for efficiency
        const recentActivity = await app_1.prisma.event.findMany({
            where: { timestamp: { gt: twentyFourHoursAgo } },
            select: { timestamp: true }
        });
        // Group by hour in JS
        const hourlyMap = new Map();
        recentActivity.forEach((e) => {
            const hour = new Date(e.timestamp).setMinutes(0, 0, 0);
            const key = new Date(hour).toISOString();
            hourlyMap.set(key, (hourlyMap.get(key) || 0) + 1);
        });
        const eventsByHour = Array.from(hourlyMap.entries())
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
