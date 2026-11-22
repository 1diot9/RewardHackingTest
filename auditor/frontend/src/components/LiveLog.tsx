import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import type { LogEvent } from '@/api'
import { cn, formatClock } from '@/lib/utils'

export const LOG_WINDOW = 100

const TONE: Record<string, string> = {
  text: 'text-foreground',
  tool: 'text-sky-300',
  tool_result: 'text-slate-400',
  round: 'text-amber-200',
  usage: 'text-emerald-300',
  error: 'text-red-300',
  stderr: 'text-orange-200',
  status: 'text-muted-foreground',
  done: 'text-muted-foreground',
}

function LogLine({ event }: { event: LogEvent }) {
  const [expanded, setExpanded] = useState(false)
  const body = event.text || ''
  const lines = body.split('\n')
  const collapsible = lines.length > 1 || body.length > 96
  const shown = expanded || !collapsible ? body : lines[0]
  const hidden = Math.max(0, lines.length - 1)

  return (
    <div
      className={cn('log-line', collapsible && 'collapsible', expanded && 'expanded')}
      onClick={collapsible ? () => setExpanded((open) => !open) : undefined}
    >
      {event.ts ? <span className="log-line-time">{formatClock(event.ts)}</span> : null}
      <span className="log-line-tag">{event.type}</span>
      <span className={cn('log-line-body', TONE[event.type] || 'text-foreground')}>{shown}</span>
      {collapsible && !expanded && hidden > 0 ? <span className="log-line-hint">还有 {hidden} 行</span> : null}
      {collapsible ? <span className="log-line-caret">{expanded ? '▾' : '▸'}</span> : null}
    </div>
  )
}

export function LiveLog({
  events,
  hasOlder,
  loadingOlder,
  onLoadOlder,
  emptyText = '等待审计输出…',
}: {
  events: LogEvent[]
  hasOlder: boolean
  loadingOlder: boolean
  onLoadOlder: () => void
  emptyText?: string
}) {
  const ref = useRef<HTMLDivElement>(null)
  const stick = useRef(true)
  const ignore = useRef(false)
  const savedTop = useRef(0)
  const prevFirst = useRef<number | undefined>(undefined)
  const prevHeight = useRef(0)
  const loadOlder = useRef(onLoadOlder)
  loadOlder.current = onLoadOlder

  useLayoutEffect(() => {
    const el = ref.current
    if (!el) return
    const first = events[0]?.seq
    const prepended = prevFirst.current != null && first != null && first < prevFirst.current
    ignore.current = true
    if (prepended) {
      el.scrollTop = savedTop.current + (el.scrollHeight - prevHeight.current)
    } else if (stick.current) {
      el.scrollTop = el.scrollHeight
    }
    prevFirst.current = first
    prevHeight.current = el.scrollHeight
    const timer = window.setTimeout(() => {
      ignore.current = false
    }, 80)
    return () => window.clearTimeout(timer)
  }, [events])

  return (
    <div>
      <div className="mb-1 text-xs text-muted-foreground">
        已显示 {events.length} 条
        {loadingOlder ? ' · 正在加载更早的记录' : hasOlder ? ' · 滚到顶部再加载 100 条' : ''}
      </div>
      <div
        ref={ref}
        className="log-view h-[32rem] overflow-auto rounded-lg ring-1 ring-foreground/10"
        onScroll={() => {
          const el = ref.current
          if (!el || ignore.current) return
          savedTop.current = el.scrollTop
          const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 48
          stick.current = atBottom
          if (!atBottom && el.scrollTop <= 1 && hasOlder && !loadingOlder) loadOlder.current()
        }}
      >
        <div className="p-3">
          {events.length === 0 ? <div className="text-muted-foreground">{emptyText}</div> : null}
          {events.map((event) => (
            <LogLine key={event.seq} event={event} />
          ))}
        </div>
      </div>
    </div>
  )
}

export function useEventStream(taskId: string, onEvent: (event: LogEvent) => void, enabled: boolean, scope: 'tasks' | 'projects' = 'tasks') {
  const handler = useRef(onEvent)
  useEffect(() => {
    handler.current = onEvent
  }, [onEvent])

  useEffect(() => {
    if (!enabled) return
    let last = 0
    let source: EventSource | null = null
    let stopped = false
    let timer = 0

    const open = () => {
      if (stopped) return
      source = new EventSource(`/api/${scope}/${taskId}/events?after=${last}`)
      source.onmessage = (message) => {
        const event = JSON.parse(message.data) as LogEvent
        last = Math.max(last, event.seq || 0)
        handler.current(event)
      }
      source.onerror = () => {
        source?.close()
        if (!stopped) timer = window.setTimeout(open, 1000)
      }
    }
    open()
    return () => {
      stopped = true
      window.clearTimeout(timer)
      source?.close()
    }
  }, [taskId, enabled, scope])
}
