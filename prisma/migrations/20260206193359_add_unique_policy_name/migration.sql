/*
  Warnings:

  - You are about to drop the column `isActive` on the `Policy` table. All the data in the column will be lost.
  - You are about to drop the column `rule` on the `Policy` table. All the data in the column will be lost.
  - A unique constraint covering the columns `[name]` on the table `Policy` will be added. If there are existing duplicate values, this will fail.
  - Added the required column `rules` to the `Policy` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "Policy" DROP COLUMN "isActive",
DROP COLUMN "rule",
ADD COLUMN     "rules" JSONB NOT NULL;

-- CreateIndex
CREATE UNIQUE INDEX "Policy_name_key" ON "Policy"("name");
