'use client'

// Password Policy tab (local build addition): Settings → Access control →
// Password Policy. Reads and writes ONLY the password-expiry tunables of the
// security_policies row via /api/v1/settings/password-policy (admin.settings
// gated, providerOnly tab). The complexity rules keep living on the
// Compliance page; this tab is about the max age and its warning window.

import { useEffect, useState } from 'react'

import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  CircularProgress,
  FormControlLabel,
  Stack,
  Switch,
  TextField,
  Typography,
} from '@mui/material'
import { useTranslations } from 'next-intl'

const MAX_AGE_MAX = 3650
const WARNING_MAX = 365

interface PasswordPolicy {
  password_max_age_days: number
  password_warning_days: number
  updated_at?: string
  updated_by?: string | null
}

export default function PasswordPolicyTab() {
  const t = useTranslations('passwordPolicy')
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [enabled, setEnabled] = useState(false)
  const [maxAgeDays, setMaxAgeDays] = useState('90')
  const [warningDays, setWarningDays] = useState('7')

  useEffect(() => {
    let cancelled = false

    fetch('/api/v1/settings/password-policy')
      .then(res => (res.ok ? res.json() : Promise.reject(new Error(`HTTP ${res.status}`))))
      .then(body => {
        if (cancelled) return
        const policy: PasswordPolicy = body?.data ?? {}
        const days = Number(policy.password_max_age_days) || 0
        setEnabled(days > 0)
        setMaxAgeDays(String(days > 0 ? days : 90))
        setWarningDays(String(Number(policy.password_warning_days) || 7))
        setLoading(false)
      })
      .catch(() => {
        if (!cancelled) {
          setError(t('loadError'))
          setLoading(false)
        }
      })

    return () => {
      cancelled = true
    }
  }, [t])

  const maxAgeInvalid = !/^\d+$/.test(maxAgeDays) || Number(maxAgeDays) > MAX_AGE_MAX
  const warningInvalid = !/^\d+$/.test(warningDays) || Number(warningDays) > WARNING_MAX
  // A warning window at or beyond the total age would warn from day zero.
  const windowInvalid =
    enabled && !maxAgeInvalid && !warningInvalid && Number(warningDays) >= Number(maxAgeDays)

  const handleSave = async () => {
    setSaving(true)
    setError('')
    setSuccess('')

    try {
      const res = await fetch('/api/v1/settings/password-policy', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          password_max_age_days: enabled ? Number(maxAgeDays) : 0,
          password_warning_days: Number(warningDays),
        }),
      })
      const body = await res.json().catch(() => null)

      if (!res.ok) {
        setError(body?.code === 'E_PASSWORD_MAX_AGE_INVALID' || body?.code === 'E_PASSWORD_WARNING_INVALID'
          ? t('invalidRange', { max: Math.max(MAX_AGE_MAX, WARNING_MAX) })
          : body?.error || t('saveError'))
        return
      }

      setSuccess(t('saved'))
    } catch {
      setError(t('saveError'))
    } finally {
      setSaving(false)
    }
  }

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', py: 8 }}>
        <CircularProgress size={28} />
      </Box>
    )
  }

  return (
    <Stack spacing={3} sx={{ maxWidth: 720 }}>
      <Card variant='outlined'>
        <CardContent>
          <Typography variant='h6' fontWeight={700} gutterBottom>
            {t('title')}
          </Typography>
          <Typography variant='body2' sx={{ opacity: 0.75, mb: 2 }}>
            {t('description')}
          </Typography>

          {error && <Alert severity='error' sx={{ mb: 2 }}>{error}</Alert>}
          {success && <Alert severity='success' sx={{ mb: 2 }}>{success}</Alert>}

          <FormControlLabel
            control={<Switch checked={enabled} onChange={e => setEnabled(e.target.checked)} />}
            label={t('enableLabel')}
            sx={{ mb: 2 }}
          />

          <Stack spacing={2}>
            <TextField
              select={false}
              label={t('maxAgeLabel')}
              value={maxAgeDays}
              onChange={e => setMaxAgeDays(e.target.value)}
              disabled={!enabled || saving}
              error={enabled && maxAgeInvalid}
              helperText={
                enabled
                  ? maxAgeInvalid
                    ? t('maxAgeError', { max: MAX_AGE_MAX })
                    : t('maxAgeHelper')
                  : t('disabledHelper')
              }
              type='number'
              size='small'
              sx={{ maxWidth: 280 }}
            />
            <TextField
              select={false}
              label={t('warningLabel')}
              value={warningDays}
              onChange={e => setWarningDays(e.target.value)}
              disabled={!enabled || saving}
              error={enabled && (warningInvalid || windowInvalid)}
              helperText={
                enabled
                  ? warningInvalid
                    ? t('warningError', { max: WARNING_MAX })
                    : windowInvalid
                      ? t('windowError')
                      : t('warningHelper')
                  : t('disabledHelper')
              }
              type='number'
              size='small'
              sx={{ maxWidth: 280 }}
            />
          </Stack>

          <Box sx={{ mt: 3, display: 'flex', gap: 2 }}>
            <Button
              variant='contained'
              onClick={handleSave}
              disabled={saving || (enabled && (maxAgeInvalid || warningInvalid || windowInvalid))}
            >
              {saving ? t('saving') : t('save')}
            </Button>
          </Box>

          <Typography variant='caption' sx={{ display: 'block', mt: 2, opacity: 0.6 }}>
            {t('note')}
          </Typography>
        </CardContent>
      </Card>
    </Stack>
  )
}
