import { Router } from 'express';
import { scanFile } from '../controllers/analysisController';
import multer from 'multer';

const router = Router();
const upload = multer({ dest: 'uploads/' });

router.post('/scan', upload.single('file'), scanFile);

export default router;
