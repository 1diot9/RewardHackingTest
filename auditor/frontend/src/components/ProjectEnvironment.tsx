import { useCallback, useEffect, useRef, useState } from 'react'
import { api, type LogEvent, type Project, type Provider } from '@/api'
import { LiveLog, LOG_WINDOW, useEventStream } from '@/components/LiveLog'
import ThreatModelEditor from '@/components/ThreatModelEditor'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'

type FileTree = { files: string[]; directories: Map<string, FileTree> }

function buildFileTree(files: string[]): FileTree {
  const root: FileTree = { files: [], directories: new Map() }
  for (const path of files) {
    const parts = path.split('/')
    const name = parts.pop()
    if (!name) continue
    let node = root
    for (const part of parts) {
      let child = node.directories.get(part)
      if (!child) {
        child = { files: [], directories: new Map() }
        node.directories.set(part, child)
      }
      node = child
    }
    node.files.push(path)
  }
  return root
}

function EnvironmentFileTree({ tree, onSelect }: { tree: FileTree; onSelect: (path: string) => void }) {
  return <ul className="grid gap-1">
    {tree.files.map((path) => <li key={path}><button type="button" className="max-w-full break-all rounded px-2 py-1 text-left text-sm hover:bg-muted focus-visible:outline focus-visible:outline-2" onClick={() => onSelect(path)}>{path.split('/').pop()}</button></li>)}
    {Array.from(tree.directories, ([name, child]) => <li key={name}><details><summary className="cursor-pointer rounded px-2 py-1 text-sm font-medium hover:bg-muted">{name}/</summary><div className="ml-4 border-l pl-2"><EnvironmentFileTree tree={child} onSelect={onSelect} /></div></details></li>)}
  </ul>
}

export default function ProjectEnvironment({ project, providers, onUpdate }: { project: Project; providers: Provider[]; onUpdate: (project: Project) => void }) {
  const [providerId, setProviderId] = useState('')
  const [model, setModel] = useState('')
  const [instruction, setInstruction] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [events, setEvents] = useState<LogEvent[]>([])
  const [streamCharacters, setStreamCharacters] = useState<number | null>(null)
  const [waitingSince, setWaitingSince] = useState<number | null>(null)
  const [now, setNow] = useState(Date.now())
  const [loadingOlder, setLoadingOlder] = useState(false)
  const [exhausted, setExhausted] = useState(false)
  const [files, setFiles] = useState<string[]>([])
  const [activeFile, setActiveFile] = useState('')
  const [fileContent, setFileContent] = useState('')
  const eventRef = useRef(events)
  const retainHistory = useRef(false)
  const loadingRef = useRef(false)
  eventRef.current = events
  const provider = providers.find((item) => item.id === providerId)
  const selected = provider?.models.find((item) => item.id === model)

  useEffect(() => {
    if (!providerId && providers[0]) {
      setProviderId(providers[0].id)
      setModel(providers[0].models[0]?.id || '')
    }
  }, [providerId, providers])

  const onEvent = useCallback((event: LogEvent) => {
    if (event.type === 'model_progress') {
      setWaitingSince(null)
      setStreamCharacters(event.characters ?? 0)
      return
    }
    if (event.type === 'model_stream_end') {
      setWaitingSince(null)
      setStreamCharacters(null)
      return
    }
    if (event.type === 'model_wait') {
      setWaitingSince(Date.parse(event.ts))
      setStreamCharacters(null)
    }
    else if (['text', 'tool', 'status', 'error', 'done'].includes(event.type)) {
      setWaitingSince(null)
      setStreamCharacters(null)
    }
    setEvents((current) => {
      if (current.some((item) => item.seq === event.seq)) return current
      const next = [...current, event]
      return !retainHistory.current && next.length > LOG_WINDOW ? next.slice(-LOG_WINDOW) : next
    })
  }, [])
  useEventStream(project.id, onEvent, true, 'projects')

  useEffect(() => {
    if (waitingSince == null) return
    setNow(Date.now())
    const timer = window.setInterval(() => setNow(Date.now()), 1000)
    return () => window.clearInterval(timer)
  }, [waitingSince])

  useEffect(() => {
    const refresh = () => api.projectEnvironmentFiles(project.id).then((result) => setFiles(result.files)).catch(() => {})
    refresh()
    const timer = window.setInterval(refresh, 4000)
    return () => window.clearInterval(timer)
  }, [project.id])

  useEffect(() => {
    if (!activeFile) return
    api.projectEnvironmentContent(project.id, activeFile).then((result) => setFileContent(result.content)).catch((err: Error) => setFileContent(err.message))
  }, [activeFile, project.id, project.initialization?.environment_status])

  const loadOlder = useCallback(() => {
    const before = eventRef.current[0]?.seq
    if (loadingRef.current || exhausted || !before || before <= 1) return
    loadingRef.current = true
    retainHistory.current = true
    setLoadingOlder(true)
    api.olderProjectEvents(project.id, before).then((result) => {
      setEvents((current) => {
        const seen = new Set(current.map((event) => event.seq))
        return [...result.events.filter((event) => !seen.has(event.seq)), ...current]
      })
      if (!result.has_more) setExhausted(true)
    }).catch((err: Error) => setError(err.message)).finally(() => { loadingRef.current = false; setLoadingOlder(false) })
  }, [exhausted, project.id])

  async function initialize() {
    setBusy(true)
    setError('')
    try {
      const form = new FormData()
      form.append('provider_id', providerId)
      form.append('model', model)
      form.append('instruction', instruction)
      onUpdate(await api.initializeProject(project.id, form))
    } catch (err) { setError(err instanceof Error ? err.message : '初始化失败') }
    finally { setBusy(false) }
  }

  const initialization = project.initialization
  const preparing = initialization?.environment_status === 'preparing'
  const pausing = initialization?.environment_status === 'pause_requested'
  const paused = initialization?.environment_status === 'paused'
  const stopping = initialization?.environment_status === 'stop_requested'
  const status = initialization?.environment_status
  const reviewItems = initialization?.threat_model_review || []
  const acknowledged = Boolean(initialization?.threat_model_ack?.digest && initialization.threat_model_ack.digest === initialization.threat_model_digest)
  const needsAcknowledgement = status === 'ready' && initialization?.coverage_status === 'review_required' && !acknowledged
  const coverageText = initialization?.coverage_status === 'closed'
    ? '角色闭包已闭合，创建审计时会使用这份威胁模型。'
    : initialization?.coverage_status === 'review_required'
      ? (acknowledged ? '威胁模型中的待复核项已确认，可以创建审计。' : '威胁模型含待复核项。确认前不能用生成的清单创建审计。')
      : ''
  const statusText = status === 'preparing' ? '正在初始化并测试' : pausing ? '暂停中，等待当前步骤结束' : paused ? '初始化已暂停' : stopping ? '停止中，等待当前步骤结束' : status === 'stopped' ? '初始化已停止' : status === 'ready' ? '环境与账号测试通过' : status === 'incomplete' ? '材料已生成，检查未通过' : status === 'failed' ? '初始化失败' : '尚未初始化'

  async function changeInitializationState(action: 'pause' | 'resume' | 'stop') {
    setBusy(true)
    setError('')
    try {
      onUpdate(action === 'pause' ? await api.pauseProjectInitialization(project.id) : action === 'stop' ? await api.stopProjectInitialization(project.id) : await api.resumeProjectInitialization(project.id))
    } catch (err) { setError(err instanceof Error ? err.message : '操作失败') }
    finally { setBusy(false) }
  }

  async function acknowledge() {
    setBusy(true)
    setError('')
    try {
      onUpdate(await api.acknowledgeThreatModel(project.id))
    } catch (err) { setError(err instanceof Error ? err.message : '确认失败') }
    finally { setBusy(false) }
  }
  const waitingSeconds = waitingSince == null ? 0 : Math.max(0, Math.floor((now - waitingSince) / 1000))

  return (
    <Card>
      <CardHeader><CardTitle>项目环境初始化</CardTitle><span className="text-sm text-muted-foreground">{statusText}</span></CardHeader>
      <CardContent className="grid min-w-0 grid-cols-1 gap-3">
        <p className="text-muted-foreground">生成 Python 环境脚本、角色闭包和 RECEIPT Manifest，自动测试环境与账号。测试通过后清理实例；失败时保留实例以便排错，最多自动修改五次。</p>
        {initialization?.github_updated && initialization.github_change_counts ? <div role="status" className="rounded-lg border border-amber-500 bg-amber-50 p-3 text-sm text-amber-900">已同步 GitHub 源码：新增 {initialization.github_change_counts.added}、修改 {initialization.github_change_counts.modified}、删除 {initialization.github_change_counts.deleted} 个文件。</div> : null}
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="grid min-w-0 grid-cols-1 gap-1.5"><Label>模型商</Label><Select value={providerId} onValueChange={(value) => { const next = value ?? ''; setProviderId(next); setModel(providers.find((item) => item.id === next)?.models[0]?.id || '') }}><SelectTrigger className="min-w-0" title={provider?.name}><SelectValue className="block min-w-0 truncate" placeholder="选择模型商">{provider?.name || '选择模型商'}</SelectValue></SelectTrigger><SelectContent>{providers.map((item) => <SelectItem key={item.id} value={item.id}>{item.name}</SelectItem>)}</SelectContent></Select></div>
          <div className="grid min-w-0 grid-cols-1 gap-1.5"><Label>模型</Label><Select value={model} onValueChange={(value) => setModel(value ?? '')}><SelectTrigger className="min-w-0" title={selected?.name || selected?.id}><SelectValue className="block min-w-0 truncate" placeholder="选择模型">{selected?.name || selected?.id || '选择模型'}</SelectValue></SelectTrigger><SelectContent>{(provider?.models || []).map((item) => <SelectItem key={item.id} value={item.id}>{item.name || item.id}</SelectItem>)}</SelectContent></Select></div>
        </div>
        <div className="grid gap-1.5"><Label htmlFor="setup-instruction">补充要求（可选）</Label><Textarea id="setup-instruction" maxLength={8000} value={instruction} onChange={(event) => setInstruction(event.target.value)} placeholder="例如：只调整 environment 目录中的启动脚本，保留其他已有文件。" /></div>
        <div className="flex flex-wrap gap-2"><Button disabled={busy || preparing || pausing || paused || stopping || !providerId || !model} onClick={() => void initialize()}>{preparing ? '初始化中…' : initialization ? '重新初始化环境' : '初始化环境'}</Button>{preparing ? <Button variant="outline" disabled={busy} onClick={() => void changeInitializationState('pause')}>暂停</Button> : null}{pausing ? <Button variant="outline" disabled>暂停中…</Button> : null}{paused || status === 'failed' ? <Button variant="outline" disabled={busy} onClick={() => void changeInitializationState('resume')}>继续初始化</Button> : null}{preparing || pausing || paused ? <Button variant="outline" disabled={busy} onClick={() => void changeInitializationState('stop')}>停止</Button> : null}{stopping ? <Button variant="outline" disabled>停止中…</Button> : null}</div>
        {status === 'failed' ? <p className="text-xs text-muted-foreground">继续初始化将使用原模型、补充要求和已有工作区；更换模型请重新初始化。</p> : null}
        {initialization ? <p className="text-xs text-muted-foreground">材料目录：{initialization.workspace}\environment。初始化模型调用会产生费用，不计入审计预算。</p> : null}
        {initialization?.checks?.map((check) => <p key={check.id} className="text-xs text-muted-foreground">{check.ok ? '✓' : '✗'} {check.message}</p>)}
        {coverageText ? <p className="text-xs text-muted-foreground">{coverageText}</p> : null}
        {reviewItems.map((item) => <p key={item.message} className="text-xs text-muted-foreground">{item.message}</p>)}
        {status === 'ready' ? <ThreatModelEditor project={project} onUpdate={onUpdate} /> : null}
        {needsAcknowledgement ? <div><Button variant="outline" disabled={busy || preparing} onClick={() => void acknowledge()}>{busy ? '确认中…' : '确认待复核项并允许创建审计'}</Button></div> : null}
        {initialization?.error || error ? <p className="text-sm text-destructive">{error || initialization?.error}</p> : null}
        {files.length > 0 ? <div className="grid min-w-0 gap-2"><h2 className="text-sm font-medium">环境文件</h2><div className="max-h-80 overflow-auto rounded-lg border p-2"><EnvironmentFileTree tree={buildFileTree(files)} onSelect={setActiveFile} /></div>{activeFile ? <div className="min-w-0"><p className="mb-1 break-all text-xs text-muted-foreground">{activeFile}</p><pre className="max-h-80 overflow-auto whitespace-pre-wrap break-all rounded-lg bg-muted p-3 text-xs">{fileContent}</pre></div> : null}</div> : null}
        <div className="min-w-0"><h2 className="mb-2 text-sm font-medium">实时输出</h2><LiveLog events={events} hasOlder={!exhausted && (events[0]?.seq ?? 1) > 1} loadingOlder={loadingOlder} onLoadOlder={loadOlder} emptyText="等待环境初始化输出…" />
          {preparing ? <p role="status" className="mt-2 flex items-center gap-2 text-sm text-muted-foreground">
            <span aria-hidden="true" className="h-3 w-3 animate-spin rounded-full border-2 border-current border-t-transparent motion-reduce:animate-none" />
            {streamCharacters != null ? `正在接收模型响应，已收到 ${streamCharacters.toLocaleString()} 个字符` : waitingSince != null ? `正在等待模型响应，已等待 ${Math.floor(waitingSeconds / 60)} 分 ${waitingSeconds % 60} 秒` : '正在初始化，等待下一条输出…'}
          </p> : null}
        </div>
      </CardContent>
    </Card>
  )
}
