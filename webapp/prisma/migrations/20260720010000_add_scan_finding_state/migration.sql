CREATE TABLE "ScanFindingState" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "findingKey" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'open',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ScanFindingState_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "ScanFindingState_scanId_findingKey_key"
ON "ScanFindingState"("scanId", "findingKey");

CREATE INDEX "ScanFindingState_userId_status_idx"
ON "ScanFindingState"("userId", "status");

ALTER TABLE "ScanFindingState"
ADD CONSTRAINT "ScanFindingState_scanId_fkey"
FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "ScanFindingState"
ADD CONSTRAINT "ScanFindingState_userId_fkey"
FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
