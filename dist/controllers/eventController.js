"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getIncidentDetails = exports.getIncidents = exports.getPolicies = exports.updateAlertStatus = exports.createPolicy = exports.getAlerts = exports.getEvents = exports.ingestEvent = void 0;
const app_1 = require("../app");
const zod_1 = require("zod");
const engine_1 = require("../utils/engine");
const eventSchema = zod_1.z.object({
    type: zod_1.z.string(),
    source: zod_1.z.string(),
    details: zod_1.z.record(zod_1.z.any()), // JSON object
    timestamp: zod_1.z.string().optional(), // ISO string
});
const ingestEvent = async (req, res) => {
    try {
        const { type, source, details, timestamp } = eventSchema.parse(req.body);
        // 1. Fetch ALL policies
        const policies = await app_1.prisma.policy.findMany({ where: { isActive: true } });
        let status = 'SAFE';
        let riskScore = 0;
        let matchedPolicy = null;
        let anomalyReason;
        // 2a. Behavioral Analysis
        const anomalyCheck = await (0, engine_1.checkBehavioralAnomaly)(source, type, details);
        if (anomalyCheck.isAnomaly) {
            status = 'MALICIOUS';
            riskScore = 50; // Use a medium score for behavioral anomaly
            anomalyReason = anomalyCheck.reason;
        }
        // 2b. Rule-Based Detection
        for (const policy of policies) {
            const rule = policy.rule;
            if (!rule || !rule.field)
                continue;
            const eventValue = details[rule.field];
            if (eventValue === undefined)
                continue;
            let isMatch = false;
            if (rule.operator === 'equals' && eventValue === rule.value)
                isMatch = true;
            if (rule.operator === 'contains' && typeof eventValue === 'string' && eventValue.includes(rule.value))
                isMatch = true;
            if (isMatch) {
                status = 'MALICIOUS';
                riskScore = 100;
                matchedPolicy = policy;
                break; // Stop on first critical match
            }
        }
        // 3. Save Event
        const event = await app_1.prisma.event.create({
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
            const aiSummary = (0, engine_1.generateAiSummary)(detectionName, source, mitreTactic, mitreTechniqueId);
            const alert = await app_1.prisma.alert.create({
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
            await (0, engine_1.correlateAlertToIncident)(alert.id, source, 'CRITICAL');
        }
        res.status(201).json({
            status: 'ok',
            eventId: event.id,
            analysis: status,
        });
    }
    catch (error) {
        console.error('Ingestion Error:', error);
        res.status(400).json({
            error: error.message || 'Ingestion failed',
        });
    }
};
exports.ingestEvent = ingestEvent;
const getEvents = async (_req, res) => {
    try {
        const events = await app_1.prisma.event.findMany({
            orderBy: { timestamp: 'desc' },
            take: 50,
        });
        res.json(events);
    }
    catch {
        res.status(500).json({ error: 'Failed to fetch events' });
    }
};
exports.getEvents = getEvents;
const getAlerts = async (_req, res) => {
    try {
        const alerts = await app_1.prisma.alert.findMany({
            include: { event: true, incident: true }, // Include incident
            orderBy: { createdAt: 'desc' },
        });
        res.json(alerts);
    }
    catch {
        res.status(500).json({ error: 'Failed to fetch alerts' });
    }
};
exports.getAlerts = getAlerts;
const createPolicy = async (req, res) => {
    try {
        const policy = await app_1.prisma.policy.create({
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
    }
    catch (error) {
        res.status(500).json({ error: 'Failed to create policy' });
    }
};
exports.createPolicy = createPolicy;
const updateAlertStatus = async (req, res) => {
    try {
        const { id } = req.params;
        const { status } = req.body;
        if (!['OPEN', 'ACKNOWLEDGED', 'RESOLVED'].includes(status)) {
            return res.status(400).json({ error: 'Invalid status' });
        }
        const alert = await app_1.prisma.alert.update({
            where: { id },
            data: { status },
        });
        res.json(alert);
    }
    catch (error) {
        res.status(500).json({ error: 'Failed to update alert status' });
    }
};
exports.updateAlertStatus = updateAlertStatus;
const getPolicies = async (_req, res) => {
    try {
        const policies = await app_1.prisma.policy.findMany({
            orderBy: { createdAt: 'desc' },
        });
        res.json(policies);
    }
    catch {
        res.status(500).json({ error: 'Failed to fetch policies' });
    }
};
exports.getPolicies = getPolicies;
// --- Incident Controllers (New) ---
const getIncidents = async (_req, res) => {
    try {
        const incidents = await app_1.prisma.incident.findMany({
            orderBy: { updatedAt: 'desc' },
            include: {
                alerts: {
                    include: { event: true } // Need event for source aggregation
                }
            }
        });
        res.json(incidents);
    }
    catch {
        res.status(500).json({ error: 'Failed to fetch incidents' });
    }
};
exports.getIncidents = getIncidents;
const getIncidentDetails = async (req, res) => {
    try {
        const { id } = req.params;
        const incident = await app_1.prisma.incident.findUnique({
            where: { id },
            include: {
                alerts: {
                    include: { event: true },
                    orderBy: { createdAt: 'asc' }
                }
            }
        });
        if (!incident)
            return res.status(404).json({ error: 'Incident not found' });
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
        const fullTimeline = [...timeline, ...eventEntries].sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
        res.json({
            ...incident,
            timeline: fullTimeline
        });
    }
    catch (error) {
        console.error('Failed to fetch incident details:', error);
        res.status(500).json({ error: 'Failed to fetch incident details' });
    }
};
exports.getIncidentDetails = getIncidentDetails;
