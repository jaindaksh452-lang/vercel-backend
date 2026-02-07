-- AlterTable
ALTER TABLE "Alert" ADD COLUMN     "aiSummary" TEXT,
ADD COLUMN     "incidentId" TEXT,
ADD COLUMN     "mitreTactic" TEXT,
ADD COLUMN     "mitreTechniqueId" TEXT,
ADD COLUMN     "mitreTechniqueName" TEXT;

-- AlterTable
ALTER TABLE "Policy" ADD COLUMN     "mitreTactic" TEXT,
ADD COLUMN     "mitreTechniqueId" TEXT,
ADD COLUMN     "mitreTechniqueName" TEXT;

-- CreateTable
CREATE TABLE "Incident" (
    "id" TEXT NOT NULL,
    "severity" "Severity" NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'OPEN',
    "summary" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Incident_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "BehavioralBaseline" (
    "id" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "metric" TEXT NOT NULL,
    "value" JSONB NOT NULL,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "BehavioralBaseline_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "BehavioralBaseline_source_metric_key" ON "BehavioralBaseline"("source", "metric");

-- AddForeignKey
ALTER TABLE "Alert" ADD CONSTRAINT "Alert_incidentId_fkey" FOREIGN KEY ("incidentId") REFERENCES "Incident"("id") ON DELETE SET NULL ON UPDATE CASCADE;
