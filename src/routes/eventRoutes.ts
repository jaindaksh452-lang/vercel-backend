import { Router } from 'express';
import { ingestEvent, getEvents, getAlerts, createPolicy, getPolicies, updateAlertStatus, getIncidents, getIncidentDetails } from '../controllers/eventController';
import { authenticateToken, requireRole } from '../middleware/authMiddleware';

const router = Router();

// Public ingestion? Or secured with API Key? For now public or basic auth is fine for MVP simulator.
// Real world: Use Service Account Token.
router.post('/ingest', ingestEvent);

// Dashboard Routes
router.get('/', authenticateToken, getEvents);
router.get('/alerts', authenticateToken, getAlerts);
router.patch('/alerts/:id/status', authenticateToken, updateAlertStatus);
router.get('/policies', authenticateToken, getPolicies);
router.post('/policies', authenticateToken, requireRole(['ADMIN']), createPolicy);

// Incident Routes
router.get('/incidents', authenticateToken, getIncidents);
router.get('/incidents/:id', authenticateToken, getIncidentDetails);

export default router;
