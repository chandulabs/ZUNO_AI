// Thin API client for ZUNO's on-premise server (zero external API keys)
const API_BASE = import.meta.env.VITE_API_URL || ''

export async function api<T = any>(path: string, init?: RequestInit): Promise<T> {
  const url = path.startsWith('http') ? path : `${API_BASE}${path}`
  const r = await fetch(url, init)
  let j: any = null
  try { j = await r.json() } catch { /* non-JSON */ }
  if (!r.ok) throw new Error((j && (j.detail?.[0]?.msg || j.detail)) || `Request failed (HTTP ${r.status})`)
  return j as T
}

export const newScanId = () =>
  (crypto as any)?.randomUUID ? (crypto as any).randomUUID() : 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => ((Math.random() * 16) | 0).toString(16))

export const STAGES = [
  'input',
  'validation',
  'normalization',
  'features',
  'rules',
  'threat_intel',
  'random_forest',
  'xgboost',
  'active_model',
  'shap',
  'risk',
  'verdict',
  'report'
]

export const VERDICT_COLOR: Record<string, string> = {
  SAFE: '#8DDB78',
  SUSPICIOUS: '#E9B96E',
  PHISHING: '#E27C75',
  UNKNOWN: '#A2ADA6'
}

export const TI_STATUS: Record<string, { label: string; color: string }> = {
  MALICIOUS: { label: 'MALICIOUS', color: '#E27C75' },
  SUSPICIOUS: { label: 'SUSPICIOUS', color: '#E9B96E' },
  NO_MATCH: { label: 'NO MATCH FOUND', color: '#B8C9AE' },
  DATABASE_EMPTY: { label: 'DATABASE EMPTY', color: '#E9B96E' },
  OFFLINE: { label: 'OFFLINE CACHE', color: '#A2ADA6' },
  DATABASE_UNAVAILABLE: { label: 'UNAVAILABLE', color: '#A2ADA6' },
  UNKNOWN: { label: 'UNKNOWN', color: '#A2ADA6' },
}

export const fmtTime = (iso?: string) => (iso ? new Date(iso).toLocaleString() : '—')
export const pct = (x: number) => `${(x * 100).toFixed(1)}%`
