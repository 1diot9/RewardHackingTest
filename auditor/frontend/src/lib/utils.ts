import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

const SHANGHAI = 'Asia/Shanghai'

export function formatTime(value: string | null | undefined): string {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleString('zh-CN', { timeZone: SHANGHAI, hour12: false })
}

export function formatClock(value: string | null | undefined): string {
  if (!value) return ''
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return ''
  return new Intl.DateTimeFormat('en-GB', {
    timeZone: SHANGHAI,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
  }).format(date)
}

export function formatDuration(totalSeconds: number): string {
  const seconds = Math.max(0, Math.floor(totalSeconds))
  const hours = Math.floor(seconds / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  const remain = seconds % 60
  if (hours > 0) return `${hours}:${String(minutes).padStart(2, '0')}:${String(remain).padStart(2, '0')}`
  return `${minutes}:${String(remain).padStart(2, '0')}`
}

export function currencyCode(currency: string): 'USD' | 'CNY' {
  const folded = (currency || '').trim().toUpperCase()
  if (folded === 'CNY' || folded === 'RMB' || currency === '人民币' || currency === '元') return 'CNY'
  return 'USD'
}

export function currencyLabel(currency: string): string {
  return currencyCode(currency) === 'CNY' ? '人民币' : '美元'
}

export function formatMoney(value: number, currency: string): string {
  const amount = Number.isFinite(value) ? value : 0
  const text = amount.toFixed(4)
  return currencyCode(currency) === 'CNY' ? `¥${text}` : `$${text}`
}

export function formatMillions(tokens: number): string {
  const millions = (Number.isFinite(tokens) ? tokens : 0) / 1_000_000
  return `${millions.toFixed(2)}M`
}

export function formatRate(part: number, total: number): string {
  if (!Number.isFinite(part) || !Number.isFinite(total) || total <= 0) return '0.0%'
  return `${((part / total) * 100).toFixed(1)}%`
}

function rateOr(value: number | null | undefined, fallback: number): number {
  return value == null || !Number.isFinite(value) ? fallback : value
}

export function usageCosts(task: {
  input_tokens: number
  output_tokens: number
  cache_read_tokens: number
  cache_write_tokens: number
  prices?: {
    input_per_mtok: number
    output_per_mtok: number
    cache_read_per_mtok: number | null
    cache_write_per_mtok: number | null
  }
}) {
  const fresh = task.input_tokens || 0
  const output = task.output_tokens || 0
  const cacheRead = task.cache_read_tokens || 0
  const cacheWrite = task.cache_write_tokens || 0
  const totalInput = fresh + cacheRead + cacheWrite
  const prices = task.prices
  const inputRate = prices?.input_per_mtok ?? 0
  const outputRate = prices?.output_per_mtok ?? 0
  const cacheReadRate = rateOr(prices?.cache_read_per_mtok, inputRate)
  const cacheWriteRate = rateOr(prices?.cache_write_per_mtok, inputRate)
  return {
    totalInput,
    output,
    cacheRead,
    cacheRate: formatRate(cacheRead, totalInput),
    inputCost: (fresh * inputRate + cacheWrite * cacheWriteRate) / 1_000_000,
    outputCost: (output * outputRate) / 1_000_000,
    cacheCost: (cacheRead * cacheReadRate) / 1_000_000,
  }
}

const STATUS_LABEL: Record<string, string> = {
  queued: '排队',
  running: '审计中',
  pause_requested: '暂停中',
  cancel_requested: '停止中',
  budget_exhausted: '预算用尽',
  time_exhausted: '时长用尽',
  cancelled: '已停止',
  completed: '已结束',
  error: '失败',
}

export function statusLabel(status: string, pauseReason?: string | null): string {
  if (status === 'draft') return '待准备'
  if (status === 'preparing') return '准备中'
  if (status === 'paused') {
    return pauseReason === 'manual' || pauseReason === 'restart' ? '已暂停' : '额度暂停'
  }
  return STATUS_LABEL[status] || status
}

export function statusVariant(status: string): 'info' | 'success' | 'warning' | 'destructive' | 'secondary' {
  if (status === 'completed') return 'success'
  if (status === 'running') return 'info'
  if (status === 'paused' || status === 'budget_exhausted' || status === 'time_exhausted') return 'warning'
  if (status === 'error') return 'destructive'
  if (status === 'queued' || status === 'pause_requested' || status === 'cancel_requested') return 'secondary'
  return 'secondary'
}

export function isLive(status: string): boolean {
  return status === 'queued' || status === 'running' || status === 'paused' || status === 'pause_requested' || status === 'cancel_requested'
}

export function taskActivityLabel(status: string, pauseReason?: string | null): string | null {
  if (status === 'pause_requested') return '暂停中'
  if (status === 'paused') {
    return pauseReason === 'manual' || pauseReason === 'restart' ? '等待继续' : '额度不足，计时已暂停'
  }
  return isLive(status) ? '进行中' : null
}

export function activeSeconds(
  task: {
    started_at: string | null
    finished_at: string | null
    status: string
    paused_at?: string | null
    paused_seconds?: number
  },
  now: number,
): number {
  if (!task.started_at) return 0
  const start = new Date(task.started_at).getTime()
  const frozen = (task.status === 'paused' || task.status === 'pause_requested') && task.paused_at
    ? new Date(task.paused_at).getTime()
    : null
  const end = task.finished_at ? new Date(task.finished_at).getTime() : (frozen ?? now)
  if (!Number.isFinite(start) || !Number.isFinite(end)) return 0
  return Math.max(0, (end - start) / 1000 - (task.paused_seconds || 0))
}
