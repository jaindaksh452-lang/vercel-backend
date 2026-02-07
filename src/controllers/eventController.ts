import { Request, Response } from 'express';
import { prisma } from '../app';
import { z } from 'zod';
import { checkBehavioralAnomaly, correlateAlertToIncident, generateAiSummary } from '../utils/engine';

const eventSchema = z.object({
    type: z.string(),
    source: z.string(),
    details: z.record(z.any()), // JSON object
    timestamp: z.string().optional(), // ISO string
});

export const ingestEvent = async (req: Request, res: Response) => {
    try {
        const { type, source, details, timestamp } = eventSchema.parse(req.body);

        // 1. Fetch ALL policies
        const policies = await prisma.policy.findMany({ where: { isActive: true } });

        let status: 'UNRESOLVED' | 'SAFE' | 'MALICIOUS' = 'SAFE';
        let riskScore = 0;
        let matchedPolicy: any = null;
        let anomalyReason: string | undefined;

        // 2a. Behavioral Analysis
        const anomalyCheck = await checkBehavioralAnomaly(source, type, details);
        if (anomalyCheck.isAnomaly) {
            status = 'MALICIOUS';
            riskScore = 50; // Use a medium score for behavioral anomaly
            anomalyReason = anomalyCheck.reason;
        }

        // 2b. Rule-Based Detection
        for (const policy of policies) {
            const rule = policy.rule as any;
            if (!rule || !rule.field) continue;
            const eventValue = details[rule.field];
            if (eventValue === undefined) continue;

            let isMatch = false;
            if (rule.operator === 'equals' && eventValue === rule.value) isMatch = true;
            if (rule.operator === 'contains' && typeof eventValue === 'string' && eventValue.includes(rule.value)) isMatch = true;

            if (isMatch) {
                status = 'MALICIOUS';
                riskScore = 100;
                matchedPolicy = policy;
                break; // Stop on first critical match
            }
        }

        // 3. Save Event
        const event = await prisma.event.create({
            data: {
                type,
                source,
                details,
                riskScore,
                status,
                timestamp: timestamp ? new Date(timestamp) : new Date(),
            },
        });

        // 4. Create Alert if Malicious
        if (status === 'MALICIOUS') {
            const detectionName = matchedPolicy ? matchedPolicy.name : 'Behavioral Anomaly';
            const message = anomalyReason ? anomalyReason : `Detected ${detectionName} from ${source}`;
            const mitreTactic = matchedPolicy ? matchedPolicy.mitreTactic : (anomalyReason ? 'Defense Evasion' : null);
            const mitreTechniqueId = matchedPolicy ? matchedPolicy.mitreTechniqueId : null;
            const mitreTechniqueName = matchedPolicy ? matchedPolicy.mitreTechniqueName : null;

            // Generate AI Summary
            const aiSummary = generateAiSummary(detectionName, source, mitreTactic, mitreTechniqueId);

            const alert = await prisma.alert.create({
                data: {
                    eventId: event.id,
                    severity: 'CRITICAL',
                    message,
                    status: 'OPEN',
                    mitreTactic,
                    mitreTechniqueId,
                    mitreTechniqueName,
                    aiSummary
                },
            });

            // 5. Correlate to Incident
            await correlateAlertToIncident(alert.id, source, 'CRITICAL');
        }

        res.status(201).json({
            status: 'ok',
            eventId: event.id,
            analysis: status,
        });
    } catch (error: any) {
        console.error('Ingestion Error:', error);
        res.status(400).json({
            error: error.message || 'Ingestion failed',
        });
    }
};

export const getEvents = async (_req: Request, res: Response) => {
    try {
        const events = await prisma.event.findMany({
            orderBy: { timestamp: 'desc' },
            take: 50,
        });
        res.json(events);
    } catch {
        res.status(500).json({ error: 'Failed to fetch events' });
    }
};

export const getAlerts = async (_req: Request, res: Response) => {
    try {
        const alerts = await prisma.alert.findMany({
            include: { event: true, incident: true }, // Include incident
            orderBy: { createdAt: 'desc' },
        });
        res.json(alerts);
    } catch {
        res.status(500).json({ error: 'Failed to fetch alerts' });
    }
};

export const createPolicy = async (req: Request, res: Response) => {
    try {
        const policy = await prisma.policy.create({
            data: {
                name: req.body.name,
                rule: req.body.rule,
                isActive: req.body.isActive ?? true,
                mitreTactic: req.body.mitreTactic,
                mitreTechniqueId: req.body.mitreTechniqueId,
                mitreTechniqueName: req.body.mitreTechniqueName
            },
        });
        res.json(policy);
    } catch (error) {
        res.status(500).json({ error: 'Failed to create policy' });
    }
};

export const updateAlertStatus = async (req: Request, res: Response) => {
    try {
        const { id } = req.params;
        const { status } = req.body;

        if (!['OPEN', 'ACKNOWLEDGED', 'RESOLVED'].includes(status)) {
            return res.status(400).json({ error: 'Invalid status' });
        }

        const alert = await prisma.alert.update({
            where: { id },
            data: { status },
        });

        res.json(alert);
    } catch (error) {
        res.status(500).json({ error: 'Failed to update alert status' });
    }
};

export const getPolicies = async (_req: Request, res: Response) => {
    try {
        const policies = await prisma.policy.findMany({
            orderBy: { createdAt: 'desc' },
        });
        res.json(policies);
    } catch {
        res.status(500).json({ error: 'Failed to fetch policies' });
    }
};

// --- Incident Controllers (New) ---

export const getIncidents = async (_req: Request, res: Response) => {
    try {
        const incidents = await prisma.incident.findMany({
            orderBy: { updatedAt: 'desc' },
            include: {
                alerts: {
                    include: { event: true } // Need event for source aggregation
                }
            }
        });
        res.json(incidents);
    } catch {
        res.status(500).json({ error: 'Failed to fetch incidents' });
    }
};

export const getIncidentDetails = async (req: Request, res: Response) => {
    try {
        const { id } = req.params;
        const incident = await prisma.incident.findUnique({
            where: { id },
            include: {
                alerts: {
                    include: { event: true },
                    orderBy: { createdAt: 'asc' }
                }
            }
        });

        if (!incident) return res.status(404).json({ error: 'Incident not found' });

        // Build a unified timeline
        // 1. Start with the alerts
        let timeline = incident.alerts.map(alert => ({
            type: 'ALERT',
            timestamp: alert.createdAt,
            severity: alert.severity,
            message: alert.message,
            mitreTactic: alert.mitreTactic,
            mitreTechniqueId: alert.mitreTechniqueId,
            source: alert.event.source,
            aiSummary: alert.aiSummary
        }));

        // 2. Add raw event context (events that triggered these alerts)
        const eventEntries = incident.alerts.map(alert => ({
            type: 'EVENT',
            timestamp: alert.event.timestamp,
            message: `Event ${alert.event.type} recorded`,
            details: alert.event.details,
            source: alert.event.source
        }));

        // Combine and sort by timestamp
        const fullTimeline = [...timeline, ...eventEntries].sort(
            (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
        );

        res.json({
            ...incident,
            timeline: fullTimeline
        });
    } catch (error) {
        console.error('Failed to fetch incident details:', error);
        res.status(500).json({ error: 'Failed to fetch incident details' });
    }
};
