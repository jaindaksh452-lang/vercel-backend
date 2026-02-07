"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.checkBehavioralAnomaly = exports.correlateAlertToIncident = exports.generateAiSummary = void 0;
const app_1 = require("../app");
// ------------------------------------------------------------------
// 1. MITRE ATT&CK Mapping & AI Summary
// ------------------------------------------------------------------
const generateAiSummary = (alertType, source, mitreTactic, mitreTechnique) => {
    // Deterministic "AI" Generation
    const tacticStr = mitreTactic ? ` utilizing ${mitreTactic} techniques (ID: ${mitreTechnique})` : '';
    // Choose template based on alert type to simulate variety
    if (alertType.includes('Anomaly')) {
        return `Behavioral Anomaly: ${source} exhibited unusual activity${tacticStr}. The system detected a deviation from historical baselines, suggesting a potential outlier event that requires manual verification.`;
    }
    const templates = [
        `Threat Intelligence analysis indicates that ${source} attempted ${alertType}${tacticStr}. This pattern is strongly associated with known malicious activity.`,
        `Security Alert: ${source} triggered a high-fidelity detection for ${alertType}. Cross-referencing with MITRE framework suggests an attempt at ${mitreTactic || 'unauthorized access'}.`,
        `Automated Response: ${alertType} was intercepted on agent ${source}. The activity matches signature T1059 (Command and Scripting Interpreter) or similar behaviors.`
    ];
    // Simple deterministic index based on source string length to avoid pure randomness during Refresh
    const index = source.length % templates.length;
    return templates[index];
};
exports.generateAiSummary = generateAiSummary;
// ------------------------------------------------------------------
// 2. Incident Correlation Engine
// ------------------------------------------------------------------
const correlateAlertToIncident = async (alertId, source, severity) => {
    // Current alert details for MITRE matching
    const currentAlert = await app_1.prisma.alert.findUnique({
        where: { id: alertId }
    });
    // Look for an active OPEN incident for this source OR same MITRE technique created in the last 5 minutes
    const timeWindow = new Date(Date.now() - 5 * 60 * 1000); // 5 mins (per user request)
    const existingIncident = await app_1.prisma.incident.findFirst({
        where: {
            status: 'OPEN',
            OR: [
                {
                    alerts: {
                        some: {
                            event: { source: source }
                        }
                    }
                },
                {
                    alerts: {
                        some: {
                            mitreTechniqueId: currentAlert?.mitreTechniqueId ? { equals: currentAlert.mitreTechniqueId } : undefined,
                            NOT: { mitreTechniqueId: null }
                        }
                    }
                }
            ],
            updatedAt: {
                gte: timeWindow
            }
        },
        include: { alerts: true }
    });
    if (existingIncident) {
        // Correlate to existing
        await app_1.prisma.alert.update({
            where: { id: alertId },
            data: { incidentId: existingIncident.id }
        });
        // Update incident severity if new alert is higher
        const currentSeverities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
        const incidentSeverityIdx = currentSeverities.indexOf(existingIncident.severity);
        const alertSeverityIdx = currentSeverities.indexOf(severity);
        const newSeverity = alertSeverityIdx > incidentSeverityIdx ? severity : existingIncident.severity;
        await app_1.prisma.incident.update({
            where: { id: existingIncident.id },
            data: {
                updatedAt: new Date(),
                severity: newSeverity
            }
        });
        return existingIncident.id;
    }
    else {
        // Create new Incident
        const summary = `Security Incident involving ${source}. Grouped via ${currentAlert?.mitreTechniqueId || 'shared source'}.`;
        const newIncident = await app_1.prisma.incident.create({
            data: {
                severity: severity,
                status: 'OPEN',
                summary: summary,
                alerts: {
                    connect: { id: alertId }
                }
            }
        });
        return newIncident.id;
    }
};
exports.correlateAlertToIncident = correlateAlertToIncident;
// ------------------------------------------------------------------
// 3. Behavioral Anomaly Detection
// ------------------------------------------------------------------
const checkBehavioralAnomaly = async (source, eventType, details) => {
    // --- Check 1: New Processes (Existing) ---
    if (eventType === 'PROCESS_SPAWN') {
        const processName = details.process;
        if (processName) {
            let baseline = await app_1.prisma.behavioralBaseline.findUnique({
                where: { source_metric: { source, metric: 'known_processes' } }
            });
            if (!baseline) {
                await app_1.prisma.behavioralBaseline.create({
                    data: { source, metric: 'known_processes', value: [processName] }
                });
            }
            else {
                const knownProcesses = baseline.value;
                if (!knownProcesses.includes(processName)) {
                    return {
                        isAnomaly: true,
                        reason: `Anomaly: New process '${processName}' executed on ${source}. Never seen in previous baselines.`
                    };
                }
            }
        }
    }
    // --- Check 2: Event Frequency (New) ---
    // Track count of events in last 60 seconds
    const oneMinuteAgo = new Date(Date.now() - 60 * 1000);
    const eventCount = await app_1.prisma.event.count({
        where: {
            source,
            timestamp: { gte: oneMinuteAgo }
        }
    });
    let volumeBaseline = await app_1.prisma.behavioralBaseline.findUnique({
        where: { source_metric: { source, metric: 'event_volume' } }
    });
    if (!volumeBaseline) {
        // Initialize volume baseline: { avg: currentCount, threshold: currentCount * 5 }
        await app_1.prisma.behavioralBaseline.create({
            data: {
                source,
                metric: 'event_volume',
                value: { avg: eventCount || 1, threshold: 20 } // Default threshold for demo
            }
        });
    }
    else {
        const stats = volumeBaseline.value;
        if (eventCount > stats.threshold) {
            return {
                isAnomaly: true,
                reason: `Anomaly: Event spike on ${source}. Frequency (${eventCount} eps) exceeds baseline threshold (${stats.threshold} eps).`
            };
        }
        // Slightly update average (very slow learning for demo)
        const newAvg = (stats.avg * 0.95) + (eventCount * 0.05);
        await app_1.prisma.behavioralBaseline.update({
            where: { id: volumeBaseline.id },
            data: { value: { avg: newAvg, threshold: Math.max(20, Math.floor(newAvg * 4)) } }
        });
    }
    return { isAnomaly: false };
};
exports.checkBehavioralAnomaly = checkBehavioralAnomaly;
