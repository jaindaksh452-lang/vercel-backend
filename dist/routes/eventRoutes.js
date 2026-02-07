"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const eventController_1 = require("../controllers/eventController");
const authMiddleware_1 = require("../middleware/authMiddleware");
const router = (0, express_1.Router)();
// Public ingestion? Or secured with API Key? For now public or basic auth is fine for MVP simulator.
// Real world: Use Service Account Token.
router.post('/ingest', eventController_1.ingestEvent);
// Dashboard Routes
router.get('/', authMiddleware_1.authenticateToken, eventController_1.getEvents);
router.get('/alerts', authMiddleware_1.authenticateToken, eventController_1.getAlerts);
router.patch('/alerts/:id/status', authMiddleware_1.authenticateToken, eventController_1.updateAlertStatus);
router.get('/policies', authMiddleware_1.authenticateToken, eventController_1.getPolicies);
router.post('/policies', authMiddleware_1.authenticateToken, (0, authMiddleware_1.requireRole)(['ADMIN']), eventController_1.createPolicy);
// Incident Routes
router.get('/incidents', authMiddleware_1.authenticateToken, eventController_1.getIncidents);
router.get('/incidents/:id', authMiddleware_1.authenticateToken, eventController_1.getIncidentDetails);
exports.default = router;
