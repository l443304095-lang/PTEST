// src/lib/compliance/policies.ts
// CRUD for security_policies (singleton row) + password validation.
//
// The table is conceptually a singleton (id='default') even after the
// multi-tenancy refactor added a `tenant_id` column — see the original
// PRIMARY KEY on id alone. We keep the tenantId argument so the call sites
// don't need to change shape during the SQLite → Postgres refactor; the
// field is filtered on but tenant-specific rows are not currently created
// elsewhere in the codebase.
//
// The public SecurityPolicies / ALLOWED_FIELDS / API JSON shape remains in
// snake_case so existing frontend code (pages/components reading the
// response) and saved settings payloads keep working unchanged. The Prisma
// client side uses camelCase; mapping happens at the boundary of this file.

import { prisma } from '@/lib/db/prisma'
import type { Prisma } from '@prisma/client'
import { invalidateTrustedProxiesCache } from '@/lib/net/clientIp'

export interface SecurityPolicies {
  id: string
  password_min_length: number
  password_require_uppercase: boolean
  password_require_lowercase: boolean
  password_require_numbers: boolean
  password_require_special: boolean
  password_max_age_days: number
  password_warning_days: number
  session_timeout_minutes: number
  session_max_concurrent: number
  login_max_failed_attempts: number
  login_lockout_duration_minutes: number
  login_ip_max_failed_attempts: number
  login_trusted_proxies: number
  audit_retention_days: number
  audit_auto_cleanup: boolean
  require_2fa_for_super_admin: boolean
  updated_at: string
  updated_by: string | null
}

type PrismaRow = Prisma.SecurityPolicyGetPayload<{}>

/**
 * Shortest audit retention accepted, in days. The API refuses a lower value
 * and the sweeper (lib/audit/retentionSweeper.ts) clamps whatever the row
 * holds, so a value saved before this floor existed can never purge faster.
 */
export const AUDIT_RETENTION_MIN_DAYS = 30
export const E_AUDIT_RETENTION_TOO_SHORT = 'E_AUDIT_RETENTION_TOO_SHORT'

/** Upper bounds accepted for the password expiry tunables (local addition). */
export const PASSWORD_MAX_AGE_MAX_DAYS = 3650
export const PASSWORD_WARNING_MAX_DAYS = 365
export const E_PASSWORD_MAX_AGE_INVALID = 'E_PASSWORD_MAX_AGE_INVALID'
export const E_PASSWORD_WARNING_INVALID = 'E_PASSWORD_WARNING_INVALID'

/** Retention days the sweeper applies for a stored value. */
export function effectiveAuditRetentionDays(days: number): number {
  return Math.max(AUDIT_RETENTION_MIN_DAYS, Math.trunc(days))
}

export interface AuditRetentionPolicy {
  autoCleanup: boolean
  retentionDays: number
}

/**
 * The global audit retention policy, as the sweeper applies it: `retentionDays`
 * is already clamped to the floor. A missing row reads as cleanup off, so a
 * database that has no policy yet never purges anything.
 */
export async function getAuditRetentionPolicy(tenantId: string = 'default'): Promise<AuditRetentionPolicy> {
  const row = await prisma.securityPolicy.findFirst({
    where: { id: 'default', tenantId },
    select: { auditAutoCleanup: true, auditRetentionDays: true },
  })
  if (!row) return { autoCleanup: false, retentionDays: effectiveAuditRetentionDays(90) }
  return { autoCleanup: row.auditAutoCleanup, retentionDays: effectiveAuditRetentionDays(row.auditRetentionDays) }
}

function assertValidAuditRetention(partial: Partial<Record<string, unknown>>): void {
  if (!('audit_retention_days' in partial)) return
  const value = partial.audit_retention_days
  if (typeof value !== 'number' || !Number.isInteger(value) || value < AUDIT_RETENTION_MIN_DAYS) {
    throw new Error(E_AUDIT_RETENTION_TOO_SHORT)
  }
}

/**
 * Validity of the password-expiry tunables (local addition): integers within
 * their bounds, 0 = disabled for the max age. Throws instead of silently
 * dropping like updateSecurityPolicies does for generic numbers, so a typo
 * in the API payload can never turn an "180 days" policy into "no policy".
 */
function assertValidPasswordExpiry(partial: Partial<Record<string, unknown>>): void {
  if ('password_max_age_days' in partial) {
    const value = partial.password_max_age_days
    const valid =
      typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= PASSWORD_MAX_AGE_MAX_DAYS
    if (!valid) throw new Error(E_PASSWORD_MAX_AGE_INVALID)
  }
  if ('password_warning_days' in partial) {
    const value = partial.password_warning_days
    const valid =
      typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= PASSWORD_WARNING_MAX_DAYS
    if (!valid) throw new Error(E_PASSWORD_WARNING_INVALID)
  }
}

export interface PasswordAgeStatus {
  /** The policy applies to this account at all. */
  enabled: boolean
  /** When the local password was last set; null = never recorded (never expires). */
  passwordChangedAt: Date | null
  /** When the password expires under the current policy; null = never. */
  expiresAt: Date | null
  /** Days left before expiry (ceil); null = never expires. */
  daysRemaining: number | null
  /** The policy's warning window, in days. */
  warningDays: number
}

/**
 * Expiry state of ONE user's local password under the CURRENT policy.
 * Shared by the login gate (config.ts) and the /auth/password-status route.
 * A missing timestamp (SSO-only accounts, pre-migration rows) never expires.
 */
export async function getUserPasswordAgeStatus(
  userId: string,
  tenantId: string = 'default',
): Promise<PasswordAgeStatus> {
  const [policy, user] = await Promise.all([
    prisma.securityPolicy.findFirst({
      where: { id: 'default', tenantId },
      select: { passwordMaxAgeDays: true, passwordWarningDays: true },
    }),
    prisma.user.findUnique({
      where: { id: userId },
      select: { passwordChangedAt: true, password: true },
    }),
  ])

  const maxAgeDays = policy?.passwordMaxAgeDays ?? 0
  const warningDays = policy?.passwordWarningDays ?? 7
  const passwordChangedAt = user?.passwordChangedAt ?? null

  if (maxAgeDays <= 0 || !passwordChangedAt) {
    return { enabled: maxAgeDays > 0, passwordChangedAt, expiresAt: null, daysRemaining: null, warningDays }
  }

  const expiresAt = new Date(passwordChangedAt.getTime() + maxAgeDays * 86_400_000)
  const daysRemaining = Math.ceil((expiresAt.getTime() - Date.now()) / 86_400_000)

  return { enabled: true, passwordChangedAt, expiresAt, daysRemaining, warningDays }
}

function rowToPolicies(row: PrismaRow): SecurityPolicies {
  return {
    id: row.id,
    password_min_length: row.passwordMinLength,
    password_require_uppercase: row.passwordRequireUppercase,
    password_require_lowercase: row.passwordRequireLowercase,
    password_require_numbers: row.passwordRequireNumbers,
    password_require_special: row.passwordRequireSpecial,
    password_max_age_days: row.passwordMaxAgeDays,
    password_warning_days: row.passwordWarningDays,
    session_timeout_minutes: row.sessionTimeoutMinutes,
    session_max_concurrent: row.sessionMaxConcurrent,
    login_max_failed_attempts: row.loginMaxFailedAttempts,
    login_lockout_duration_minutes: row.loginLockoutDurationMinutes,
    login_ip_max_failed_attempts: row.loginIpMaxFailedAttempts,
    login_trusted_proxies: row.loginTrustedProxies,
    audit_retention_days: row.auditRetentionDays,
    audit_auto_cleanup: row.auditAutoCleanup,
    require_2fa_for_super_admin: row.require2faForSuperAdmin,
    updated_at: row.updatedAt.toISOString(),
    updated_by: row.updatedBy,
  }
}

export async function getSecurityPolicies(tenantId: string = 'default'): Promise<SecurityPolicies> {
  // Try the tenant-scoped row first; fall back to the global default if the
  // tenant hasn't customised security policies. The table is a singleton in
  // practice (id PK = 'default') so the tenant filter is a no-op today, but
  // keep it for forward compatibility with the locked multi-tenant decision.
  let row = await prisma.securityPolicy.findFirst({
    where: { id: 'default', tenantId },
  })
  if (!row && tenantId !== 'default') {
    row = await prisma.securityPolicy.findFirst({
      where: { id: 'default', tenantId: 'default' },
    })
  }
  if (!row) throw new Error('Security policies not initialized')
  return rowToPolicies(row)
}

// Snake-case (frontend / API payload) → camelCase (Prisma) field mapping.
// Centralised so a future field rename touches one place. Keep in sync with
// the Prisma model: any new column needs an entry here AND in rowToPolicies.
const SNAKE_TO_CAMEL: Record<string, keyof Prisma.SecurityPolicyUpdateInput> = {
  password_min_length: 'passwordMinLength',
  password_require_uppercase: 'passwordRequireUppercase',
  password_require_lowercase: 'passwordRequireLowercase',
  password_require_numbers: 'passwordRequireNumbers',
  password_require_special: 'passwordRequireSpecial',
  password_max_age_days: 'passwordMaxAgeDays',
  password_warning_days: 'passwordWarningDays',
  session_timeout_minutes: 'sessionTimeoutMinutes',
  session_max_concurrent: 'sessionMaxConcurrent',
  login_max_failed_attempts: 'loginMaxFailedAttempts',
  login_lockout_duration_minutes: 'loginLockoutDurationMinutes',
  login_ip_max_failed_attempts: 'loginIpMaxFailedAttempts',
  login_trusted_proxies: 'loginTrustedProxies',
  audit_retention_days: 'auditRetentionDays',
  audit_auto_cleanup: 'auditAutoCleanup',
  require_2fa_for_super_admin: 'require2faForSuperAdmin',
}

/**
 * Foot-shoot guard: enabling the global 2FA-for-super_admin policy is
 * refused when the actor doesn't have 2FA on their own account. Anything
 * other than a false→true transition on this flag is a no-op.
 */
async function assertCanEnable2faPolicy(
  partial: Partial<Record<string, unknown>>,
  userId: string,
  tenantId: string,
): Promise<void> {
  if (partial.require_2fa_for_super_admin !== true) return
  const current = await prisma.securityPolicy.findFirst({
    where: { id: 'default', tenantId },
    select: { require2faForSuperAdmin: true },
  })
  if (!current || current.require2faForSuperAdmin) return
  const actor = await prisma.user.findUnique({
    where: { id: userId },
    select: { totpEnabled: true },
  })
  if (!actor?.totpEnabled) {
    throw new Error('E_NEED_OWN_2FA')
  }
}

export async function updateSecurityPolicies(
  partial: Partial<Record<string, unknown>>,
  userId: string,
  tenantId: string = 'default',
): Promise<SecurityPolicies> {
  // Refused outright rather than dropped like the other tunables: the sweeper
  // deletes rows for good, so a too-short value must never be saved silently.
  assertValidAuditRetention(partial)
  assertValidPasswordExpiry(partial)
  await assertCanEnable2faPolicy(partial, userId, tenantId)

  const data: Prisma.SecurityPolicyUpdateInput = {}

  for (const [snake, camel] of Object.entries(SNAKE_TO_CAMEL)) {
    if (!(snake in partial)) continue
    const val = partial[snake]
    if (typeof val === 'boolean') {
      ;(data as any)[camel] = val
      continue
    }
    if (typeof val === 'number') {
      // Reject NaN / negative numeric tunables; drop the field rather than
      // surfacing a 500 from the DB constraint check downstream.
      if (Number.isNaN(val) || val < 0) continue
      ;(data as any)[camel] = val
    }
  }

  // Nothing valid in the payload → return current state untouched.
  if (Object.keys(data).length === 0) {
    return getSecurityPolicies(tenantId)
  }

  data.updatedAt = new Date()
  data.updatedBy = userId

  // updateMany so we can scope on (id, tenantId) without hitting the unique
  // constraint shape on id alone. Idempotent: if no row exists, nothing
  // happens and getSecurityPolicies below will throw "not initialized".
  await prisma.securityPolicy.updateMany({
    where: { id: 'default', tenantId },
    data,
  })
  invalidateTrustedProxiesCache()

  return getSecurityPolicies(tenantId)
}

export interface PasswordValidationResult {
  valid: boolean
  errors: string[]
}

export async function validatePassword(
  password: string,
  policies?: SecurityPolicies,
): Promise<PasswordValidationResult> {
  const p = policies || (await getSecurityPolicies())
  const errors: string[] = []

  if (password.length < p.password_min_length) {
    errors.push(`min_length:${p.password_min_length}`)
  }
  if (p.password_require_uppercase && !/[A-Z]/.test(password)) {
    errors.push('require_uppercase')
  }
  if (p.password_require_lowercase && !/[a-z]/.test(password)) {
    errors.push('require_lowercase')
  }
  if (p.password_require_numbers && !/\d/.test(password)) {
    errors.push('require_numbers')
  }
  if (p.password_require_special && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    errors.push('require_special')
  }

  return { valid: errors.length === 0, errors }
}
