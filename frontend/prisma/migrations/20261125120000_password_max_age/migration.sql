-- Password expiry policy (local build addition).
-- security_policies gains the tunables (0 = disabled by default so an upgrade
-- never locks anyone out); users gains the timestamp of the last local
-- password set. Existing local-password accounts are backdated to
-- created_at: their password is as old as the account, which is the honest
-- age a "days since the password was set" policy must count from.

ALTER TABLE "security_policies" ADD COLUMN "password_max_age_days" INTEGER NOT NULL DEFAULT 0;
ALTER TABLE "security_policies" ADD COLUMN "password_warning_days" INTEGER NOT NULL DEFAULT 7;

ALTER TABLE "users" ADD COLUMN "password_changed_at" TIMESTAMP(3);

UPDATE "users" SET "password_changed_at" = "created_at" WHERE "password" IS NOT NULL;
