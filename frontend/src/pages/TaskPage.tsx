import { useCallback, useEffect, useRef, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { api, type AuditTask, type EnvironmentCheck, type HumanReview, type LogEvent, type Report } from '@/api'
import { LiveLog, LOG_WINDOW, useEventStream } from '@/components/LiveLog'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { activeSeconds, formatDuration, formatMillions, formatMoney, statusLabel, statusVariant, taskActivityLabel, usageCosts } from '@/lib/utils'

function reviewLabel(status: Report['review_status']) {
  if (status === 'passed') return '审核通过'
  if (status === 'failed') return '审核不通过'
  if (status === 'audit_failed') return '审计不通过'
  return '待验证'
}

function reviewVariant(status: Report['review_status']) {
  if (status === 'passed') return 'success'
  if (status === 'failed' || status === 'audit_failed') return 'destructive'
  return 'warning'
}

const humanStatuses: { value: HumanReview['status']; label: string }[] = [
  { value: 'unreviewed', label: '未研判' },
  { value: 'confirmed', label: '确认漏洞' },
  { value: 'false_positive', label: '误报' },
  { value: 'uncertain', label: '需进一步确认' },
]

export default function TaskPage() {
  const { id = '' } = useParams()
  const [task, setTask] = useState<AuditTask | null>(null)
  const [events, setEvents] = useState<LogEvent[]>([])
  const [streamCharacters, setStreamCharacters] = useState<number | null>(null)
  const [loadingOlder, setLoadingOlder] = useState(false)
  const [olderExhausted, setOlderExhausted] = useState(false)
  const eventsRef = useRef(events)
  const retainHistory = useRef(false)
  const loadingOlderRef = useRef(false)
  eventsRef.current = events
  const [reports, setReports] = useState<Report[]>([])
  const [active, setActive] = useState('')
  const [content, setContent] = useState('')
  const [humanReview, setHumanReview] = useState<HumanReview>({ status: 'unreviewed', comment: '' })
  const [reviewBusy, setReviewBusy] = useState(false)
  const [reviewMessage, setReviewMessage] = useState('')
  const [error, setError] = useState('')
  const [now, setNow] = useState(Date.now())
  const [actionBusy, setActionBusy] = useState(false)
  const [check, setCheck] = useState<EnvironmentCheck | null>(null)
  const [manifest, setManifest] = useState('')
  const [followUp, setFollowUp] = useState('')
  const [extraBudget, setExtraBudget] = useState('0')
  const [extraMinutes, setExtraMinutes] = useState('0')

  const refresh = useCallback(() => {
    api.task(id).then(setTask).catch((err: Error) => setError(err.message))
    api.reports(id).then((result) => setReports(result.reports)).catch(() => {})
  }, [id])

  useEffect(() => {
    refresh()
    const timer = window.setInterval(refresh, 3000)
    return () => window.clearInterval(timer)
  }, [refresh])

  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000)
    return () => window.clearInterval(timer)
  }, [])

  useEffect(() => {
    setEvents([])
    setStreamCharacters(null)
    setOlderExhausted(false)
    retainHistory.current = false
  }, [id])

  useEffect(() => {
    if (task && task.status !== 'running') setStreamCharacters(null)
  }, [task?.status])

  const onEvent = useCallback((event: LogEvent) => {
    if (event.type === 'model_progress') {
      setStreamCharacters(event.characters ?? 0)
      return
    }
    if (event.type === 'model_stream_end') {
      setStreamCharacters(null)
      return
    }
    setEvents((current) => {
      if (current.some((item) => item.seq === event.seq)) return current
      const next = [...current, event]
      if (!retainHistory.current && next.length > LOG_WINDOW) return next.slice(-LOG_WINDOW)
      return next
    })
  }, [])
  useEventStream(id, onEvent, Boolean(id))

  const loadOlder = useCallback(() => {
    if (loadingOlderRef.current || olderExhausted) return
    const before = eventsRef.current[0]?.seq
    if (before == null || before <= 1) {
      setOlderExhausted(true)
      return
    }
    retainHistory.current = true
    loadingOlderRef.current = true
    setLoadingOlder(true)
    api
      .olderEvents(id, before)
      .then((result) => {
        setEvents((current) => {
          const seen = new Set(current.map((item) => item.seq))
          const older = result.events.filter((item) => !seen.has(item.seq))
          return [...older, ...current]
        })
        if (!result.has_more) setOlderExhausted(true)
      })
      .catch(() => {})
      .finally(() => {
        loadingOlderRef.current = false
        setLoadingOlder(false)
      })
  }, [id, olderExhausted])

  useEffect(() => {
    if (!active) return
    api.artifact(id, active).then((file) => setContent(file.content)).catch((err: Error) => setContent(err.message))
  }, [active, id, reports])

  if (!task) {
    return <p className="text-sm text-muted-foreground">{error || '加载任务…'}</p>
  }

  const elapsed = activeSeconds(task, now)
  const budgetPct = Math.min(100, (task.spent / task.budget) * 100)
  const timePct = Math.min(100, (elapsed / task.duration_seconds) * 100)
  const usage = usageCosts(task)
  const canPause = task.status === 'queued' || task.status === 'running'
  const canResume = task.status === 'paused' && (task.pause_reason === 'manual' || task.pause_reason === 'restart')
  const activityLabel = taskActivityLabel(task.status, task.pause_reason)
  const unpassedCount = reports.filter((report) => report.review_status !== 'passed').length
  const invalidLimits = extraBudget.trim() === '' || !Number.isFinite(Number(extraBudget)) || Number(extraBudget) < 0 || extraMinutes.trim() === '' || !Number.isInteger(Number(extraMinutes)) || Number(extraMinutes) < 0 || Number(extraMinutes) > 10080

  async function changeTaskState(action: 'pause' | 'resume' | 'stop') {
    setActionBusy(true)
    setError('')
    try {
      const updated = action === 'pause' ? await api.pauseTask(id) : action === 'stop' ? await api.stopTask(id) : await api.resumeTask(id)
      setTask(updated)
    } catch (err) {
      setError(err instanceof Error ? err.message : '操作失败')
    } finally {
      setActionBusy(false)
    }
  }

  async function preparationAction(action: 'prepare' | 'check' | 'start') {
    setActionBusy(true)
    setError('')
    try {
      if (action === 'prepare') { setCheck(null); setTask(await api.prepareTask(id)) }
      if (action === 'check') { setCheck(await api.checkTask(id, manifest || task?.receipt_manifest || '')); refresh() }
      if (action === 'start') setTask(await api.startTask(id))
    } catch (err) { setError(err instanceof Error ? err.message : '操作失败') }
    finally { setActionBusy(false) }
  }

  async function submitFollowUp() {
    setActionBusy(true)
    setError('')
    try {
      setTask(await api.followUpTask(id, { instruction: followUp, budget: Number(extraBudget), duration_minutes: Number(extraMinutes) }))
      setFollowUp('')
    } catch (err) { setError(err instanceof Error ? err.message : '提交失败') }
    finally { setActionBusy(false) }
  }

  async function reviewReports(all: boolean) {
    setActionBusy(true)
    setError('')
    try {
      const limits = { budget: Number(extraBudget), duration_minutes: Number(extraMinutes) }
      setTask(await (all ? api.reviewAllTask(id, limits) : api.reviewPendingTask(id, limits)))
    } catch (err) { setError(err instanceof Error ? err.message : '提交失败') }
    finally { setActionBusy(false) }
  }

  function selectReport(report: Report) {
    if (report.path === active) return
    setActive(report.path)
    setContent('')
    setHumanReview(report.human_review ?? { status: 'unreviewed', comment: '' })
    setReviewMessage('')
  }

  async function saveHumanReview() {
    const path = active
    setReviewBusy(true)
    setReviewMessage('')
    try {
      const saved = await api.saveHumanReview(id, path, humanReview)
      setReports((current) => current.map((report) => report.path === path ? { ...report, human_review: saved } : report))
      setReviewMessage('人工研判已保存')
    } catch (err) {
      setReviewMessage(err instanceof Error ? err.message : '保存失败')
    } finally { setReviewBusy(false) }
  }

  return (
    <div className="flex flex-col gap-4">
      {task.github_updated ? <div role="status" className="rounded-lg border border-amber-500 bg-amber-50 p-3 text-sm text-amber-900">GitHub 默认分支的源码相对上次同步已有更新（首次同步与导入版本比较），本次审计使用已同步的最新源码，Agent 会被提醒检查原有漏洞是否仍然存在。项目初始化生成的环境配置可能需要重新检查。</div> : null}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <Link to={task.project_id ? `/projects/${task.project_id}` : '/'} className="text-xs text-muted-foreground hover:text-foreground">返回{task.project_id ? '项目' : '列表'}</Link>
          <h1 className="mt-1 text-xl font-semibold">{task.project_name || task.model}</h1>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{task.instruction}</p>
          <p className="mt-1 text-xs text-muted-foreground">完成模式：{task.completion_mode === 'agent' ? 'Agent 自主完成' : '持续审计'}</p>
          {task.automatic_environment && task.base_url ? <p className="mt-1 text-xs text-muted-foreground">靶场：{task.base_url}；账号记录：{task.workspace}\runtime\receipt-run.json</p> : null}
          {task.environment_status === 'stopped' ? <p className="mt-1 text-xs text-muted-foreground">靶场环境已停止</p> : task.requires_environment_setup && !task.environment_ready ? (
            <p className="mt-1 text-xs text-muted-foreground">{task.status === 'preparing' ? '正在启动环境并验证账号' : '等待环境启动'}</p>
          ) : null}
        </div>
        <div className="flex items-center gap-2">
          <Badge variant={statusVariant(task.status)}>{statusLabel(task.status, task.pause_reason)}</Badge>
          {canPause ? (
            <Button variant="outline" disabled={actionBusy} onClick={() => void changeTaskState('pause')}>
              {actionBusy ? '处理中…' : '暂停'}
            </Button>
          ) : canResume ? (
            <Button disabled={actionBusy} onClick={() => void changeTaskState('resume')}>
              {actionBusy ? '处理中…' : '继续'}
            </Button>
          ) : null}
          {canPause || task.status === 'paused' ? (
            <Button variant="outline" disabled={actionBusy} onClick={() => void changeTaskState('stop')}>
              {actionBusy ? '处理中…' : '停止本轮'}
            </Button>
          ) : null}
        </div>
      </div>

      {['completed', 'budget_exhausted', 'time_exhausted', 'cancelled', 'error'].includes(task.status) ? (
        <Card><CardHeader><CardTitle>继续处理已有审计</CardTitle></CardHeader><CardContent className="grid gap-3">
          <p className="text-sm text-muted-foreground">复用现有工作区和报告，重新启动靶场，并在原有限额上追加预算和时长。</p>
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" onClick={() => setFollowUp('清单文件已更新。请检查相关清单和已有漏洞，按更新后的要求修改必要文件，重新提交验证，并根据结果更新报告。')}>清单文件已更新</Button>
            <Button variant="outline" onClick={() => setFollowUp('RECEIPT 基础设施问题已修复。请重新检查已有漏洞和验证结果，修改必要的 PoC 或清单后重新提交验证，并根据结果更新报告。')}>RECEIPT 问题已修复</Button>
            <Button variant="outline" onClick={() => setFollowUp('请重新检查已有漏洞，修正必要的报告、PoC 和清单，然后提交验证并根据实际结果更新报告。')}>重新检查已有漏洞</Button>
          </div>
          <div className="grid gap-1.5"><Label htmlFor="follow-up">后续指令</Label><Textarea id="follow-up" maxLength={8000} value={followUp} onChange={(event) => setFollowUp(event.target.value)} placeholder="描述需要检查或修改的文件及验证要求" /></div>
          <div className="grid gap-3 sm:grid-cols-2"><div className="grid gap-1.5"><Label htmlFor="extra-budget">追加预算（{task.currency}）</Label><Input id="extra-budget" type="number" min="0" step="0.01" value={extraBudget} onChange={(event) => setExtraBudget(event.target.value)} /></div><div className="grid gap-1.5"><Label htmlFor="extra-minutes">追加时长（分钟）</Label><Input id="extra-minutes" type="number" min="0" max="10080" step="1" value={extraMinutes} onChange={(event) => setExtraMinutes(event.target.value)} /></div></div>
          <div className="flex flex-wrap items-center gap-3">
            <Button disabled={actionBusy || !followUp.trim() || invalidLimits} onClick={() => void submitFollowUp()}>提交后续指令</Button>
            {task.receipt_enabled ? <Button variant="outline" disabled={actionBusy || invalidLimits || unpassedCount === 0} onClick={() => void reviewReports(false)}>重新验证所有未审核通过的报告（{unpassedCount}）</Button> : null}
            {task.receipt_enabled ? <Button variant="outline" disabled={actionBusy || invalidLimits || reports.length === 0} onClick={() => void reviewReports(true)}>重新验证所有报告（{reports.length}）</Button> : null}
          </div>
          <p className="text-xs text-muted-foreground">继续处理时自动使用项目最新环境文件并重新准备靶场。</p>
        </CardContent></Card>
      ) : null}

      {(task.status === 'draft' || task.status === 'preparing') ? (
        <Card><CardHeader><CardTitle>审计前准备</CardTitle></CardHeader><CardContent className="grid gap-3">
          {task.automatic_environment ? <>
            <p>使用项目初始化生成的脚本启动环境并验证账号。启动失败时不会开始审计。</p>
            {task.status === 'draft' ? <Button disabled={actionBusy} onClick={() => void preparationAction('start')}>重试启动</Button> : null}
          </> : <>
          <p>工作区：{task.workspace}。可在其 environment 目录自行准备文件，或使用 Agent 生成。</p>
          <p className="text-muted-foreground">需要 Compose 配置、启动脚本、账号创建脚本和 READY.md。项目初始化会测试环境与账号；此处检查只验证文件及基础配置。</p>
          {task.receipt_enabled ? <Input value={manifest} placeholder={task.receipt_manifest || '可信 RECEIPT Manifest 文件名'} onChange={(event) => setManifest(event.target.value)} /> : null}
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" disabled={actionBusy || task.status !== 'draft'} onClick={() => void preparationAction('prepare')}>使用 Agent 准备</Button>
            <Button variant="outline" disabled={actionBusy || task.status !== 'draft'} onClick={() => void preparationAction('check')}>检查准备情况</Button>
            <Button disabled={actionBusy || task.status !== 'draft' || !task.environment_ready} onClick={() => void preparationAction('start')}>{actionBusy ? '处理中…' : '开始审计'}</Button>
          </div>
          {check ? <div><p>{check.notice}</p>{check.checks.map((item) => <p key={item.id}>{item.ok ? '✓' : '✗'} {item.message}</p>)}</div> : null}
          </>}
        </CardContent></Card>
      ) : null}

      <div className="grid gap-3 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>预算</CardTitle>
            <span className="text-sm text-muted-foreground">{formatMoney(task.spent, task.currency)} / {formatMoney(task.budget, task.currency)}</span>
          </CardHeader>
          <CardContent>
            <div className="h-1.5 overflow-hidden rounded-full bg-muted">
              <div className="h-full bg-primary" style={{ width: `${budgetPct}%` }} />
            </div>
            <div className="mt-3 grid grid-cols-3 gap-2 text-xs">
              <div>
                <p className="text-muted-foreground">输入</p>
                <p className="mt-0.5 font-medium">{formatMillions(usage.totalInput)}</p>
                <p className="text-muted-foreground">{formatMoney(usage.inputCost, task.currency)}</p>
              </div>
              <div>
                <p className="text-muted-foreground">输出</p>
                <p className="mt-0.5 font-medium">{formatMillions(usage.output)}</p>
                <p className="text-muted-foreground">{formatMoney(usage.outputCost, task.currency)}</p>
              </div>
              <div>
                <p className="text-muted-foreground">缓存命中</p>
                <p className="mt-0.5 font-medium">{usage.cacheRate}</p>
                <p className="text-muted-foreground">{formatMoney(usage.cacheCost, task.currency)}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>时长</CardTitle>
            <span className="text-sm text-muted-foreground">{formatDuration(elapsed)} / {formatDuration(task.duration_seconds)}</span>
          </CardHeader>
          <CardContent>
            <div className="h-1.5 overflow-hidden rounded-full bg-muted">
              <div className="h-full bg-primary" style={{ width: `${timePct}%` }} />
            </div>
            <p className="mt-2 text-xs text-muted-foreground">
              {task.status === 'paused' || task.status === 'pause_requested'
                ? activityLabel
                : `${task.project_name || '历史任务'} · ${task.provider_name}`}
            </p>
            {task.context_window_tokens && task.compact_percent ? (
              <p className="mt-1 text-xs text-muted-foreground">
                上下文 {task.context_window_tokens.toLocaleString()} token · {task.compact_percent}% 时压缩
              </p>
            ) : null}
            {task.receipt_enabled ? (
              <p className="mt-1 text-xs text-muted-foreground">
                验证器已启用{task.receipt_manifest ? ` · ${task.receipt_manifest}` : ''}
              </p>
            ) : null}
          </CardContent>
        </Card>
      </div>
      {task.error ? <p className="text-sm text-amber-200">{task.error}</p> : null}
      {error ? <p className="text-sm text-destructive">{error}</p> : null}

      <div className="flex flex-col gap-4">
        <section>
          <h2 className="mb-2 text-sm font-medium">实时输出</h2>
          <LiveLog
            events={events}
            hasOlder={!olderExhausted && (events[0]?.seq ?? 1) > 1}
            loadingOlder={loadingOlder}
            onLoadOlder={loadOlder}
          />
          {task.status === 'running' ? (
            <p role="status" className="mt-2 flex items-center gap-2 text-sm text-muted-foreground">
              <span aria-hidden="true" className="h-3 w-3 animate-spin rounded-full border-2 border-current border-t-transparent motion-reduce:animate-none" />
              {streamCharacters == null ? '正在审计，等待下一条输出…' : `正在接收模型响应，已收到 ${streamCharacters.toLocaleString()} 个字符`}
            </p>
          ) : null}
        </section>
        <section className="flex min-h-0 flex-col gap-2">
          <h2 className="text-sm font-medium">漏洞报告</h2>
          <Card>
            <CardContent className="flex max-h-40 flex-col gap-1 overflow-auto">
              {reports.length === 0 ? <span className="text-muted-foreground">还没有漏洞报告</span> : null}
              {reports.map((report) => (
                <button
                  key={report.path}
                  type="button"
                  disabled={reviewBusy}
                  className={`flex shrink-0 items-center justify-between gap-2 rounded-md px-2 py-1 text-left text-xs leading-5 hover:bg-muted ${active === report.path ? 'bg-muted' : ''}`}
                  onClick={() => selectReport(report)}
                >
                  <span className="truncate">{report.title}</span>
                  <span className="flex shrink-0 flex-wrap gap-1">
                    {report.human_review ? <Badge variant="outline">人工：{humanStatuses.find((item) => item.value === report.human_review?.status)?.label}</Badge> : null}
                    {task.receipt_enabled ? <Badge variant={reviewVariant(report.review_status)}>{reviewLabel(report.review_status)}</Badge> : null}
                  </span>
                </button>
              ))}
            </CardContent>
          </Card>
          {active ? <Card><CardContent className="grid gap-3">
            <div className="text-sm font-medium">人工研判</div>
            <div className="flex flex-wrap gap-2" role="group" aria-label="人工研判结果">
              {humanStatuses.map((item) => <Button key={item.value} type="button" disabled={reviewBusy} variant={humanReview.status === item.value ? 'default' : 'outline'} aria-pressed={humanReview.status === item.value} onClick={() => { setReviewMessage(''); setHumanReview((current) => ({ ...current, status: item.value })) }}>{item.label}</Button>)}
            </div>
            <div className="grid gap-1.5"><Label htmlFor="human-review-comment">研判注释</Label><Textarea id="human-review-comment" disabled={reviewBusy} maxLength={8000} value={humanReview.comment} onChange={(event) => { setReviewMessage(''); setHumanReview((current) => ({ ...current, comment: event.target.value })) }} placeholder="记录研判依据或补充说明" /></div>
            <div className="flex items-center gap-3"><Button disabled={reviewBusy} onClick={() => void saveHumanReview()}>{reviewBusy ? '保存中…' : '保存人工研判'}</Button><span role="status" className="text-sm text-muted-foreground">{reviewMessage}</span></div>
          </CardContent></Card> : null}
          {reports.find((report) => report.path === active)?.verification_paths.filter((path) => path.verdict !== 'NOT_RUN').map((path) => (
            <div key={path.path_id} className="rounded-md border px-3 py-2 text-xs leading-5">
              <div className="font-medium">{path.path_id} · {path.verdict}</div>
              <div>攻击者角色：{path.attacker_role ?? '未记录'}；受害者角色：{path.victim_role ?? '未记录'}</div>
              <div>权限前提：使用上述可信清单指定的身份{path.accept_self_xss ? '；允许 self-XSS' : ''}</div>
              {path.reason ? <div>原因：{path.reason}</div> : null}
            </div>
          ))}
          <div className="prose-audit max-h-[24rem] overflow-auto rounded-lg bg-card p-3 ring-1 ring-foreground/10">
            {active ? (
              <ReactMarkdown remarkPlugins={[remarkGfm]}>{content}</ReactMarkdown>
            ) : (
              <p className="text-muted-foreground">选择报告查看漏洞详情。</p>
            )}
          </div>
        </section>
      </div>
    </div>
  )
}
