ALTER TABLE "User"
ADD COLUMN "onboardingCompleted" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN "onboardingGoal" TEXT;
