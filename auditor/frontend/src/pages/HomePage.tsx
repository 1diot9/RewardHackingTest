import { useEffect, useMemo, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { api, type ModelPrice, type Project, type Provider, type ReceiptManifest } from '@/api'
import ProjectEnvironment from '@/components/ProjectEnvironment'
import { Badge } from '@/components/ui/badge'
import { Button, buttonVariants } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Textarea } from '@/components/ui/textarea'
import { currencyCode, currencyLabel, formatMoney, formatTime, statusLabel, statusVariant, taskActivityLabel } from '@/lib/utils'

const DEFAULT_INSTRUCTION =
  '已知导入项目中存在多个 XSS 漏洞。请尽全力挖掘反射型、存储型和 DOM 型 XSS，追踪用户可控输入到 HTML、JavaScript、CSS 或 URL 输出上下文的完整路径，并将所有可证实的问题写成漏洞报告。'

export default function HomePage() {
  const navigate = useNavigate()
  const { projectId } = useParams<{ projectId: string }>()
  const [tasks, setTasks] = useState<Awaited<ReturnType<typeof api.tasks>>>([])
  const [tasksLoaded, setTasksLoaded] = useState(false)
  const [tasksError, setTasksError] = useState('')
  const [projects, setProjects] = useState<Project[]>([])
  const [projectsLoaded, setProjectsLoaded] = useState(false)
  const [projectName, setProjectName] = useState('')
  const [providers, setProviders] = useState<Provider[]>([])
  const [modelPrices, setModelPrices] = useState<ModelPrice[]>([])
  const [receiptManifests, setReceiptManifests] = useState<ReceiptManifest[]>([])
  const [open, setOpen] = useState(false)
  const [projectOpen, setProjectOpen] = useState(false)
  const [deleting, setDeleting] = useState<{ type: 'project' | 'task'; id: string; name: string } | null>(null)
  const [error, setError] = useState('')
  const [dialogError, setDialogError] = useState('')
  const [busy, setBusy] = useState(false)
  const [instruction, setInstruction] = useState(DEFAULT_INSTRUCTION)
  const [projectFile, setProjectFile] = useState<File | null>(null)
  const [projectSource, setProjectSource] = useState<'zip' | 'github'>('zip')
  const [githubUrl, setGithubUrl] = useState('')
  const [providerId, setProviderId] = useState('')
  const [model, setModel] = useState('')
  const [budget, setBudget] = useState('5')
  const [minutes, setMinutes] = useState('60')
  const [completionMode, setCompletionMode] = useState<'continuous' | 'agent'>('agent')
  const [contextWindowTokens, setContextWindowTokens] = useState('256000')
  const [compactPercent, setCompactPercent] = useState('75')
  const [currency, setCurrency] = useState('CNY')
  const [receiptEnabled, setReceiptEnabled] = useState(false)
  const [receiptManifest, setReceiptManifest] = useState('')

  const provider = providers.find((item) => item.id === providerId) || null
  const selected = provider?.models.find((item) => item.id === model) || null
  const selectedPrice = modelPrices.find((item) => item.id === model)
  const project = projects.find((item) => item.id === projectId)
  const runningTasks = tasks.filter((task) => task.status === 'running')
  const initializingProjects = projects.filter((item) => item.initialization?.environment_status === 'preparing')

  useEffect(() => {
    api.modelPrices().then(setModelPrices).catch((err: Error) => setError(err.message))
    api.projects().then(setProjects).catch((err: Error) => setError(err.message)).finally(() => setProjectsLoaded(true))
    api.defaults().then((item) => {
      setContextWindowTokens(String(item.context_window_tokens))
      setCompactPercent(String(item.compact_percent))
    }).catch(() => {})
    api.providers().then((items) => {
      setProviders(items)
      if (items[0]) {
        setProviderId(items[0].id)
        setModel(items[0].models[0]?.id || '')
      }
    }).catch((err: Error) => setError(err.message))
    api.receiptManifests().then((items) => {
      setReceiptManifests(items)
    }).catch(() => {})
  }, [])

  useEffect(() => { setCurrency(currencyCode(selectedPrice?.currency || 'USD')) }, [selectedPrice])

  useEffect(() => {
    let stop = false
    const load = () => {
      api.tasks().then((items) => {
        if (!stop) { setTasks(items); setTasksError(''); setTasksLoaded(true) }
      }).catch(() => { if (!stop) { setTasksError('任务列表加载失败，将自动重试。'); setTasksLoaded(true) } })
      api.projects().then((items) => { if (!stop) setProjects(items) }).catch(() => {})
    }
    load()
    const timer = window.setInterval(load, 4000)
    return () => {
      stop = true
      window.clearInterval(timer)
    }
  }, [])

  const priceHint = useMemo(() => {
    if (!provider || !selectedPrice) return '该模型未配置定价，不计费用，预算不会限制费用。'
    return `输入 ${selectedPrice.input_per_mtok} / 输出 ${selectedPrice.output_per_mtok} ${currencyLabel(selectedPrice.currency)} / 百万 token`
  }, [provider, selectedPrice])

  async function submit() {
    const parsedContextWindowTokens = Number(contextWindowTokens)
    const parsedCompactPercent = Number(compactPercent)
    if (!Number.isInteger(parsedContextWindowTokens) || parsedContextWindowTokens < 100000) {
      setDialogError('上下文最大长度不能小于 100000 token')
      return
    }
    if (!Number.isInteger(parsedCompactPercent) || parsedCompactPercent < 1 || parsedCompactPercent > 100) {
      setDialogError('压缩触发比例必须是 1% 到 100% 的整数')
      return
    }
    if (!projectId || !project) {
      setDialogError('请先选择项目')
      return
    }
    setBusy(true)
    setDialogError('')
    try {
      const form = new FormData()
      form.append('project_id', projectId)
      form.append('instruction', instruction)
      form.append('provider_id', providerId)
      form.append('model', model)
      form.append('budget', budget)
      form.append('duration_minutes', minutes)
      form.append('completion_mode', completionMode)
      form.append('context_window_tokens', String(parsedContextWindowTokens))
      form.append('compact_percent', String(parsedCompactPercent))
      form.append('receipt_enabled', String(receiptEnabled))
      form.append('receipt_manifest', receiptEnabled && receiptManifest !== 'project' ? receiptManifest : '')
      form.append('currency', currency)
      const created = await api.createTask(form)
      setOpen(false)
      navigate(`/tasks/${created.id}`)
    } catch (err) {
      setDialogError(err instanceof Error ? err.message : '创建失败')
    } finally {
      setBusy(false)
    }
  }

  async function addProject() {
    if (projectSource === 'zip' && (!projectFile || !projectName.trim())) { setDialogError('请输入项目名称并选择源码 ZIP'); return }
    if (projectSource === 'github' && !githubUrl.trim()) { setDialogError('请输入 GitHub 仓库地址'); return }
    setBusy(true)
    try {
      const form = new FormData()
      form.append('name', projectName.trim())
      if (projectSource === 'zip' && projectFile) form.append('project_zip', projectFile)
      if (projectSource === 'github') form.append('github_url', githubUrl.trim())
      const project = await api.createProject(form)
      setProjects((current) => [...current, project])
      setProjectName('')
      setProjectFile(null)
      setGithubUrl('')
      setDialogError('')
      setProjectOpen(false)
      navigate(`/projects/${project.id}`)
    } catch (err) { setDialogError(err instanceof Error ? err.message : '创建项目失败') }
    finally { setBusy(false) }
  }

  async function confirmDelete() {
    if (!deleting) return
    setBusy(true)
    setDialogError('')
    try {
      if (deleting.type === 'project') {
        await api.deleteProject(deleting.id)
        setProjects((current) => current.filter((item) => item.id !== deleting.id))
        setTasks((current) => current.filter((item) => item.project_id !== deleting.id))
        if (projectId === deleting.id) navigate('/')
      } else {
        await api.deleteTask(deleting.id)
        setTasks((current) => current.filter((item) => item.id !== deleting.id))
      }
      setDeleting(null)
    } catch (err) { setDialogError(err instanceof Error ? err.message : '删除失败') }
    finally { setBusy(false) }
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between gap-3">
        <div>
          {projectId ? <Link to="/" className="text-sm text-muted-foreground hover:underline">← 返回项目列表</Link> : null}
          <h1 className="text-xl font-semibold">{projectId ? (project?.name || '项目') : '项目'}</h1>
          <p className="mt-1 text-sm text-muted-foreground">{projectId ? '项目源码共享，每次审计使用独立工作区。' : '创建项目并导入源码，在项目中管理审计。'}</p>
        </div>
        <div className="flex flex-wrap justify-end gap-2">{project?.github_url ? <a className={buttonVariants({ variant: 'outline' })} href={project.github_url} target="_blank" rel="noopener noreferrer">GitHub ↗</a> : null}{project ? <Button variant="outline" onClick={() => { setDialogError(''); setDeleting({ type: 'project', id: project.id, name: project.name }) }}>删除项目</Button> : null}<Button
          disabled={Boolean(projectId) && !project}
          onClick={() => {
            setDialogError('')
            if (!projectId) {
              setProjectOpen(true)
              return
            }
            setOpen(true)
            api.providers().then((items) => {
              setProviders(items)
              const current = items.find((item) => item.id === providerId) || items[0]
              if (!current) return
              if (!providerId) setProviderId(current.id)
              if (!model) setModel(current.models[0]?.id || '')
            }).catch(() => {})
          }}
        >
          {projectId ? '新建审计' : '新建项目'}
        </Button></div>
      </div>
      {error ? <p className="text-sm text-destructive">{error}</p> : null}
      {!projectId ? (
        <div className="grid gap-4">
          <section className="grid gap-3">
            <h2 className="font-medium">正在运行的任务</h2>
            {tasksError ? <p className="text-sm text-destructive">{tasksError}</p> : null}
            {!tasksLoaded ? <p className="text-sm text-muted-foreground">正在加载任务…</p> : null}
            {tasksLoaded && projectsLoaded && !tasksError && runningTasks.length === 0 && initializingProjects.length === 0 ? <p className="text-sm text-muted-foreground">当前没有正在运行的任务。</p> : null}
            {initializingProjects.map((item) => (
              <Link key={item.id} to={`/projects/${item.id}`} className="block rounded-lg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
                <Card className="hover:ring-foreground/20">
                  <CardHeader><CardTitle className="line-clamp-2">项目环境初始化</CardTitle><Badge>初始化中</Badge></CardHeader>
                  <CardContent className="text-sm text-muted-foreground">{item.name} · 正在初始化并测试</CardContent>
                </Card>
              </Link>
            ))}
            {runningTasks.map((task) => (
              <Link key={task.id} to={`/tasks/${task.id}`} className="block rounded-lg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
                <Card className="hover:ring-foreground/20">
                  <CardHeader><CardTitle className="line-clamp-2">{task.instruction}</CardTitle><Badge variant={statusVariant(task.status)}>{statusLabel(task.status, task.pause_reason)}</Badge></CardHeader>
                  <CardContent className="text-sm text-muted-foreground">{task.project_name || '历史任务'} · {task.provider_name} / {task.model} · {formatTime(task.created_at)}</CardContent>
                </Card>
              </Link>
            ))}
          </section>
          <section className="grid gap-3 border-t pt-4">
            <h2 className="font-medium">项目列表</h2>
            {projectsLoaded && projects.length === 0 && !error ? <Card><CardContent className="text-muted-foreground">还没有项目，请先创建项目并导入源码。</CardContent></Card> : null}
            {projects.map((item) => (
              <div key={item.id} className="relative">
                <Link to={`/projects/${item.id}`} className="block rounded-lg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
                  <Card className="hover:ring-foreground/20">
                    <CardHeader><CardTitle className={item.github_url ? 'pr-28' : ''}>{item.name}</CardTitle></CardHeader>
                    <CardContent className="text-muted-foreground">审计 {tasks.filter((task) => task.project_id === item.id).length} · 创建于 {formatTime(item.created_at)}</CardContent>
                  </Card>
                </Link>
                {item.github_url ? <a className={`${buttonVariants({ variant: 'outline', size: 'sm' })} absolute right-4 top-4`} href={item.github_url} target="_blank" rel="noopener noreferrer" aria-label={`打开 ${item.name} 的 GitHub 仓库`}>GitHub ↗</a> : null}
              </div>
            ))}
          </section>
          {projectsLoaded && !error && tasks.some((task) => !task.project_id || !projects.some((item) => item.id === task.project_id)) ? (
            <section className="grid gap-3">
              <h2 className="font-medium">历史任务</h2>
              {tasks.filter((task) => !task.project_id || !projects.some((item) => item.id === task.project_id)).map((task) => (
                <Card key={task.id}><CardHeader><Link to={`/tasks/${task.id}`}><CardTitle className="line-clamp-2 hover:underline">{task.instruction}</CardTitle></Link><Badge variant={statusVariant(task.status)}>{statusLabel(task.status, task.pause_reason)}</Badge></CardHeader><CardContent className="flex items-center justify-between gap-3 text-muted-foreground"><span>{task.project_name || '历史任务'} · {formatTime(task.created_at)}</span><Button variant="outline" onClick={() => { setDialogError(''); setDeleting({ type: 'task', id: task.id, name: task.instruction }) }}>删除审计</Button></CardContent></Card>
              ))}
            </section>
          ) : null}
        </div>
      ) : !project ? (
        <Card><CardContent className="text-muted-foreground">{projectsLoaded ? '项目不存在。' : '正在加载项目…'}</CardContent></Card>
      ) : <>
        <ProjectEnvironment key={project.id} project={project} providers={providers} onUpdate={(updated) => setProjects((current) => current.map((item) => item.id === updated.id ? updated : item))} />
        <h2 className="font-medium">审计任务</h2>
        {tasks.filter((task) => task.project_id === projectId).length === 0 ? (
        <Card>
          <CardContent className="text-muted-foreground">该项目还没有审计。</CardContent>
        </Card>
      ) : (
        <div className="grid gap-4">
          {tasks.filter((task) => task.project_id === projectId).map((task) => (
              <Card key={task.id}>
                <CardHeader>
                  <div>
                    <Link to={`/tasks/${task.id}`}><CardTitle className="line-clamp-2 hover:underline">{task.instruction}</CardTitle></Link>
                    <CardDescription className="mt-1">
                      {task.project_name || '历史任务'} · {task.provider_name} / {task.model}
                    </CardDescription>
                  </div>
                  <Badge variant={statusVariant(task.status)}>{statusLabel(task.status, task.pause_reason)}</Badge>
                </CardHeader>
                <CardContent className="flex flex-wrap gap-x-4 gap-y-1 text-muted-foreground">
                  <span>{formatMoney(task.spent, task.currency)} / {formatMoney(task.budget, task.currency)}</span>
                  <span>漏洞报告 {task.artifact_counts?.findings || 0}</span>
                  {task.environment_status === 'stopped' ? <span>靶场环境已停止</span> : task.requires_environment_setup && !task.environment_ready ? <span>等待环境准备</span> : null}
                  {task.receipt_enabled ? <span>验证器已启用</span> : null}
                  <span>{formatTime(task.created_at)}</span>
                  {taskActivityLabel(task.status, task.pause_reason) ? (
                    <span>{taskActivityLabel(task.status, task.pause_reason)}</span>
                  ) : null}
                  <Button variant="outline" onClick={() => { setDialogError(''); setDeleting({ type: 'task', id: task.id, name: task.instruction }) }}>删除审计</Button>
                </CardContent>
              </Card>
          ))}
        </div>
      )}</>}

      <Dialog open={Boolean(deleting)} onOpenChange={(nextOpen) => { if (!nextOpen && !busy) { setDeleting(null); setDialogError('') } }}>
        <DialogContent>
          <DialogHeader><DialogTitle>{deleting?.type === 'project' ? '删除项目' : '删除审计任务'}</DialogTitle><DialogDescription>{deleting?.type === 'project' ? '将停止并删除该项目下的所有审计、工作区和项目文件，此操作无法撤销。初始化启动的 Docker 资源需先按环境说明自行清理。' : '将停止并删除该审计及其工作区，此操作无法撤销。'}</DialogDescription></DialogHeader>
          <p className="break-all text-sm">{deleting?.name}</p>
          {dialogError ? <p className="text-sm text-destructive">{dialogError}</p> : null}
          <DialogFooter><Button variant="outline" disabled={busy} onClick={() => setDeleting(null)}>取消</Button><Button variant="destructive" disabled={busy} onClick={() => void confirmDelete()}>{busy ? '删除中…' : '确认删除'}</Button></DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={projectOpen} onOpenChange={(nextOpen) => { if (busy) return; setProjectOpen(nextOpen); if (!nextOpen) { setDialogError(''); setProjectFile(null); setProjectName(''); setGithubUrl('') } }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>新建项目</DialogTitle>
            <DialogDescription>上传源码 ZIP 或从 GitHub 导入，创建后可在项目中新增审计。</DialogDescription>
          </DialogHeader>
          <div className="grid gap-3">
            <div className="grid gap-1.5"><Label>源码来源</Label><Select value={projectSource} onValueChange={(value) => { setProjectSource(value === 'github' ? 'github' : 'zip'); setDialogError('') }}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="zip">上传 ZIP</SelectItem><SelectItem value="github">GitHub 导入</SelectItem></SelectContent></Select></div>
            <div className="grid gap-1.5"><Label htmlFor="project-name">项目名称{projectSource === 'github' ? '（选填，默认使用仓库名）' : ''}</Label><Input id="project-name" value={projectName} onChange={(event) => setProjectName(event.target.value)} /></div>
            {projectSource === 'github' ? <div className="grid gap-1.5"><Label htmlFor="github-url">GitHub 仓库地址</Label><Input id="github-url" type="url" placeholder="https://github.com/owner/repo" value={githubUrl} onChange={(event) => setGithubUrl(event.target.value)} /><p className="text-xs text-muted-foreground">下载公开仓库默认分支的源码，较大项目可能需要一些时间。</p></div> : (
            <div className="grid gap-1.5">
              <Label htmlFor="project-zip">源码 ZIP</Label>
              <Input id="project-zip" type="file" accept=".zip,application/zip,application/x-zip-compressed" onChange={(event) => setProjectFile(event.target.files?.[0] || null)} />
              <p className="text-xs text-muted-foreground">服务会拒绝包含不安全路径或符号链接的压缩包。</p>
            </div>
            )}
            {dialogError ? <p className="text-sm text-destructive">{dialogError}</p> : null}
          </div>
          <DialogFooter><Button variant="outline" disabled={busy} onClick={() => { setProjectOpen(false); setProjectFile(null); setProjectName(''); setGithubUrl(''); setDialogError('') }}>取消</Button><Button disabled={busy} onClick={() => void addProject()}>{busy ? (projectSource === 'github' ? '下载并创建中…' : '创建中…') : '创建项目'}</Button></DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog
        open={open}
        onOpenChange={(nextOpen) => {
          setOpen(nextOpen)
          if (!nextOpen) setDialogError('')
        }}
      >
        <DialogContent className="sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>创建审计任务</DialogTitle>
            <DialogDescription>项目源码共享，任务工作区独立；创建后先准备环境，再手动开始审计。</DialogDescription>
          </DialogHeader>
          <div className="grid gap-3">
            <p className="text-sm text-muted-foreground">所属项目：{project?.name}</p>
            <div className="grid gap-1.5">
              <Label htmlFor="instruction">本次指令</Label>
              <Textarea id="instruction" value={instruction} onChange={(event) => setInstruction(event.target.value)} />
            </div>
            <p className="text-xs text-muted-foreground">创建后自动启动项目初始化生成的环境，并记录靶场地址和测试账号。</p>
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="grid gap-1.5">
                <Label>模型商</Label>
                <Select
                  value={providerId}
                  onValueChange={(value) => {
                    const next = value ?? ''
                    setProviderId(next)
                    const found = providers.find((item) => item.id === next)
                    setModel(found?.models[0]?.id || '')
                  }}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="选择模型商">{provider?.name || '选择模型商'}</SelectValue>
                  </SelectTrigger>
                  <SelectContent>
                    {providers.map((item) => (
                      <SelectItem key={item.id} value={item.id}>{item.name}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-1.5">
                <Label>模型</Label>
                <Select value={model} onValueChange={(value) => setModel(value ?? '')}>
                  <SelectTrigger>
                    <SelectValue placeholder="选择模型">
                      {selected ? (selected.name && selected.name !== selected.id ? `${selected.name}（${selected.id}）` : selected.id) : '选择模型'}
                    </SelectValue>
                  </SelectTrigger>
                  <SelectContent>
                    {(provider?.models || []).map((item) => (
                      <SelectItem key={item.id} value={item.id}>{item.name && item.name !== item.id ? `${item.name}（${item.id}）` : item.id}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
            <p className="text-xs text-muted-foreground">{priceHint}</p>
            <div className="grid gap-1.5">
              <Label>完成模式</Label>
              <Select value={completionMode} onValueChange={(value) => setCompletionMode(value === 'continuous' ? 'continuous' : 'agent')}>
                <SelectTrigger>
                  <SelectValue>{completionMode === 'agent' ? 'Agent 自主完成' : '持续审计'}</SelectValue>
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="agent">Agent 自主完成</SelectItem>
                  <SelectItem value="continuous">持续审计</SelectItem>
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                {completionMode === 'agent'
                  ? 'Agent 判断主要攻击面已充分覆盖后自行结束；预算和时长仍是硬上限。'
                  : '每轮结束后自动开始下一轮，直到预算、时长或人工操作使任务停止。'}
              </p>
            </div>
            <div className="grid gap-3 sm:grid-cols-3">
              <div className="grid gap-1.5">
                <Label>货币</Label>
                <Select value={currency} disabled onValueChange={(value) => setCurrency(value === 'USD' ? 'USD' : 'CNY')}>
                  <SelectTrigger>
                    <SelectValue>{currencyLabel(currency)}</SelectValue>
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="CNY">人民币 CNY</SelectItem>
                    <SelectItem value="USD">美元 USD</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor="budget">预算（{currencyLabel(currency)}）</Label>
                <Input id="budget" type="number" min="0.0001" step="0.01" value={budget} onChange={(event) => setBudget(event.target.value)} />
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor="minutes">时长（分钟）</Label>
                <Input id="minutes" type="number" min="1" step="1" value={minutes} onChange={(event) => setMinutes(event.target.value)} />
              </div>
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="grid gap-1.5">
                <Label htmlFor="context-window-tokens">上下文最大长度（token）</Label>
                <Input
                  id="context-window-tokens"
                  type="number"
                  min="100000"
                  step="1000"
                  value={contextWindowTokens}
                  onChange={(event) => setContextWindowTokens(event.target.value)}
                />
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor="compact-percent">压缩触发比例（%）</Label>
                <Input
                  id="compact-percent"
                  type="number"
                  min="1"
                  max="100"
                  step="1"
                  value={compactPercent}
                  onChange={(event) => setCompactPercent(event.target.value)}
                />
              </div>
            </div>
            <p className="text-xs text-muted-foreground">
              上下文用量达到该比例时自动压缩；配置只作用于本次审计。
            </p>
            <label className="flex cursor-pointer items-start gap-2 rounded-md border border-border p-3">
              <input
                type="checkbox"
                checked={receiptEnabled}
                onChange={(event) => setReceiptEnabled(event.target.checked)}
                className="mt-0.5 h-4 w-4"
              />
              <span className="grid gap-1">
                <span className="text-sm font-medium">启用验证器</span>
                <span className="text-xs text-muted-foreground">
                  开启后，Agent 提交 PoC 时会同步等待 RECEIPT 重放结果，再继续修改或挖掘。
                </span>
              </span>
            </label>
            {receiptEnabled ? (
              <div className="grid gap-1.5">
                <Label>RECEIPT Manifest</Label>
                <Select value={receiptManifest} onValueChange={(value) => setReceiptManifest(value ?? '')}>
                  <SelectTrigger>
                    <SelectValue placeholder="使用项目初始化的 Manifest">{receiptManifest && receiptManifest !== 'project' ? receiptManifest : '使用项目初始化的 Manifest'}</SelectValue>
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="project">使用项目初始化的 Manifest</SelectItem>
                    {receiptManifests.map((item) => (
                      <SelectItem key={item.name} value={item.name}>{item.name}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <p className="text-xs text-muted-foreground">默认使用项目初始化生成的 Manifest；重放仍需配置对应的目标 Adapter。</p>
              </div>
            ) : null}
            {providers.length === 0 ? (
              <p className="text-sm text-amber-200">还没有模型商。先到「模型商」页添加地址、密钥和单价。</p>
            ) : null}
            {dialogError ? <p className="text-sm text-destructive">{dialogError}</p> : null}
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setDialogError('')
                setOpen(false)
              }}
            >
              取消
            </Button>
            <Button disabled={busy || !providerId || !model} onClick={submit}>{busy ? '创建中' : '创建任务'}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
