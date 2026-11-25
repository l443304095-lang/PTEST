// GET/PUT /api/v1/settings/password-policy (local build addition)
//
// Reads and writes ONLY the password-expiry tunables of security_policies
// (password_max_age_days, password_warning_days). Deliberately separate from
// /api/v1/compliance/policies, which gates on ADMIN_COMPLIANCE: the expiry
// settings belong to access administration (admin.settings), so an
// installation can run a password-expiry policy without opening the whole
// compliance module.
import { NextResponse } from 'next/server'
import { getServerSession } from 'next-auth'

import { authOptions } from '@/lib/auth/config'
import { checkPermission, PERMISSIONS } from '@/lib/rbac'
import { getCurrentTenantId } from '@/lib/tenant'
import { audit } from '@/lib/audit'
import {
  E_PASSWORD_MAX_AGE_INVALID,
  E_PASSWORD_WARNING_INVALID,
  getSecurityPolicies,
  updateSecurityPolicies,
} from '@/lib/compliance/policies'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

export async function GET() {
  try {
    const denied = await checkPermission(PERMISSIONS.ADMIN_SETTINGS)
    if (denied) return denied

    const tenantId = await getCurrentTenantId()
    const policies = await getSecurityPolicies(tenantId)

    return NextResponse.json({
      data: {
        password_max_age_days: policies.password_max_age_days,
        password_warning_days: policies.password_warning_days,
        updated_at: policies.updated_at,
        updated_by: policies.updated_by,
      },
    })
  } catch (e: any) {
    console.error('Error fetching password policy:', e)
    return NextResponse.json({ error: e?.message || 'Internal server error' }, { status: 500 })
  }
}

export async function PUT(req: Request) {
  try {
    const denied = await checkPermission(PERMISSIONS.ADMIN_SETTINGS)
    if (denied) return denied

    const session = await getServerSession(authOptions)
    if (!session?.user?.id) {
      return NextResponse.json({ error: 'Not authenticated' }, { status: 401 })
    }

    const body = await req.json().catch(() => null)
    if (!body || typeof body !== 'object') {
      return NextResponse.json({ error: 'Invalid JSON body' }, { status: 400 })
    }

    // Whitelist: only the two expiry tunables pass through, whatever else the
    // payload carries (a hidden compliance field, an id, an audit stamp).
    const allowed = ['password_max_age_days', 'password_warning_days'] as const
    const partial: Record<string, unknown> = {}
    for (const key of allowed) {
      if (key in body) partial[key] = (body as Record<string, unknown>)[key]
    }

    const tenantId = await getCurrentTenantId()
    const updated = await updateSecurityPolicies(partial, session.user.id, tenantId)

    await audit({
      action: 'update',
      category: 'security',
      resourceType: 'security_policies',
      resourceId: 'default',
      resourceName: 'Password policy',
      details: partial,
    })

    return NextResponse.json({
      data: {
        password_max_age_days: updated.password_max_age_days,
        password_warning_days: updated.password_warning_days,
        updated_at: updated.updated_at,
        updated_by: updated.updated_by,
      },
    })
  } catch (e: any) {
    if (e?.message === E_PASSWORD_MAX_AGE_INVALID || e?.message === E_PASSWORD_WARNING_INVALID) {
      return NextResponse.json({ error: e.message, code: e.message }, { status: 400 })
    }
    console.error('Error updating password policy:', e)
    return NextResponse.json({ error: e?.message || 'Internal server error' }, { status: 500 })
  }
}
