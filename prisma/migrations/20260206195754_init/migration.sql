/*
  Warnings:

  - You are about to drop the column `rules` on the `Policy` table. All the data in the column will be lost.
  - Added the required column `rule` to the `Policy` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "Policy" DROP COLUMN "rules",
ADD COLUMN     "isActive" BOOLEAN NOT NULL DEFAULT true,
ADD COLUMN     "rule" JSONB NOT NULL;
