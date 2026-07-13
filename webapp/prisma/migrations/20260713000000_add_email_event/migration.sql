-- AlterTable
ALTER TABLE "User" ADD COLUMN "lifecycleOptOut" BOOLEAN NOT NULL DEFAULT false;

-- CreateTable
CREATE TABLE "EmailEvent" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "sentAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "EmailEvent_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "EmailEvent_userId_idx" ON "EmailEvent"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "EmailEvent_userId_type_key" ON "EmailEvent"("userId", "type");

-- AddForeignKey
ALTER TABLE "EmailEvent" ADD CONSTRAINT "EmailEvent_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
