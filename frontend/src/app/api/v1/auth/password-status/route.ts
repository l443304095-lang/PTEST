// GET /api/v1/auth/password-status (local build addition)
//
// The signed-in user's own password-expiry state under the current policy.
// The profile page uses it for the "your password expires in N days" banner.
// Anonymous or SSO-only accounts get a disabled status, never an error, so
// the client can render it unconditionally.
import { NextResponse } from 'next/server'
import { getServerSession } from 'next-auth'

import { authOptions } from '@/lib/auth/config'
import { getCurrentTenantId } from '@/lib/tenant'
import { getUserPasswordAgeStatus } from '@/lib/compliance/policies'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

export async function GET() {
  try {
    const session = await getServerSession(authOptions)
    if (!session?.user?.id) {
      return NextResponse.json({ data: { enabled: false, authenticated: false } })
    }

    const tenantId = await getCurrentTenantId().catch(() => 'default')
    const status = await getUserPasswordAgeStatus(session.user.id, tenantId)

    return NextResponse.json({
      data: {
        enabled: status.enabled,
        authenticated: true,
        passwordChangedAt: status.passwordChangedAt?.toISOString() ?? null,
        expiresAt: status.expiresAt?.toISOString() ?? null,
        daysRemaining: status.daysRemaining,
        warningDays: status.warningDays,
      },
    })
  } catch (e: any) {
    console.error('Error fetching password status:', e)
    return NextResponse.json({ error: e?.message || 'Internal server error' }, { status: 500 })
  }
}
