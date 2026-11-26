export type ModelPrice = {
  id: string
  name: string
  input_per_mtok: number
  output_per_mtok: number
  cache_read_per_mtok: number | null
  cache_write_per_mtok: number | null
  currency: string
}

export type Provider = {
  id: string
  name: string
  model: string
  base_url: string
  currency: string
  has_key: boolean
  key_hint: string
  catalog: RemoteModel[]
  models: ModelPrice[]
}

export type RemoteModel = {
  id: string
  name: string
}

export type ProbeResult = {
  ok: boolean
  message: string
  status: number
  latency_ms: number
  models: RemoteModel[]
}

export type PauseReason = 'manual' | 'quota' | 'restart'

export type AuditTask = {
  id: string
  project_id?: string
  instruction: string
  base_url: string
  project_name?: string
  source_dir?: string
  github_updated?: boolean
  provider_id: string
  provider_name: string
  model: string
  prices?: {
    input_per_mtok: number
    output_per_mtok: number
    cache_read_per_mtok: number | null
    cache_write_per_mtok: number | null
  }
  currency: string
  budget: number
  duration_seconds: number
  completion_mode?: 'continuous' | 'agent'
  context_window_tokens?: number
  compact_percent?: number
  receipt_enabled?: boolean
  receipt_manifest?: string
  requires_environment_setup?: boolean
  automatic_environment?: boolean
  environment_ready?: boolean
  environment_status?: string
  status: string
  stop_reason: string | null
  spent: number
  input_tokens: number
  output_tokens: number
  cache_read_tokens: number
  cache_write_tokens: number
  round: number
  artifact_counts: { findings: number; pocs: number }
  created_at: string
  started_at: string | null
  finished_at: string | null
  paused_at?: string | null
  paused_seconds?: number
  pause_reason?: PauseReason | null
  error: string | null
  workspace: string
}

export type LogEvent = {
  seq: number
  ts: string
  type: string
  text: string
  status?: string
  characters?: number
}

export type Report = {
  path: string
  title: string
  poc_id: string | null
  review_status: 'passed' | 'failed' | 'audit_failed' | 'pending' | null
  human_review: HumanReview | null
  verification_paths: {
    path_id: string
    verdict: 'ACCEPTED' | 'REJECTED' | 'INDETERMINATE' | 'NOT_RUN'
    reason: string
    attacker_principal: string
    victim_principal: string
    attacker_role: string | null
    victim_role: string | null
    accept_self_xss: boolean
  }[]
}

export type HumanReview = { status: 'unreviewed' | 'confirmed' | 'false_positive' | 'uncertain'; comment: string }

export type ReceiptManifest = {
  name: string
  size: number
  mtime: number
}

export type ReceiptSettings = {
  has_evidence_hmac_key: boolean
  evidence_hmac_key_hint: string
  evidence_hmac_key_source: 'settings' | 'environment' | 'none'
  attacker_image: string
  attacker_image_source: 'settings' | 'environment' | 'none'
  ready: boolean
  issues: string[]
}

export type ThreatReview = { code: string; message: string }
export type Project = { id: string; name: string; source_dir: string; github_url?: string; created_at: string; initialization?: { status: string; environment_status: string; error?: string | null; workspace: string; github_updated?: boolean; github_change_counts?: { added: number; modified: number; deleted: number }; checks?: { id: string; ok: boolean; message: string }[]; coverage_status?: string; threat_model_digest?: string; threat_model_review?: ThreatReview[]; threat_model_ack?: { digest: string; acknowledged_at: string; coverage_status?: string } } }
export type ThreatRole = { id: string; disposition: string; reason: string; evidence: { kind: string; path: string; literal: string } }
export type EnvironmentCheck = { ready: boolean; checks: { id: string; ok: boolean; message: string }[]; workspace: string; notice: string }

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const isFormData = init?.body instanceof FormData
  const response = await fetch(url, {
    ...init,
    headers: {
      ...(isFormData ? {} : { 'Content-Type': 'application/json' }),
      ...(init?.headers || {}),
    },
  })
  if (!response.ok) {
    if (response.status === 405 && init?.method === 'DELETE' && /^\/api\/(projects|tasks)\//.test(url)) {
      throw new Error('当前后端未加载删除接口，请重启审计器后重试。')
    }
    let detail = response.statusText
    try {
      const body = await response.json()
      detail = body.detail || detail
    } catch {
      /* 非 JSON 错误页 */
    }
    throw new Error(typeof detail === 'string' ? detail : '请求失败')
  }
  return response.json() as Promise<T>
}

export const api = {
  concurrencySettings: () => request<{ max_concurrent: number }>('/api/settings/concurrency'),
  proxySettings: () => request<{ enabled: boolean; url: string; no_proxy: string }>('/api/settings/proxy'),
  saveProxySettings: (body: { enabled: boolean; url: string; no_proxy: string }) => request<typeof body>('/api/settings/proxy', { method: 'PUT', body: JSON.stringify(body) }),
  saveConcurrencySettings: (max_concurrent: number) => request<{ max_concurrent: number }>('/api/settings/concurrency', { method: 'PUT', body: JSON.stringify({ max_concurrent }) }),
  health: () => request<{ ok: boolean; sdk: boolean }>('/api/health'),
  defaults: () => request<{
    base_url: string
    context_window_tokens: number
    compact_percent: number
  }>('/api/defaults'),
  receiptSettings: () => request<ReceiptSettings>('/api/receipt/settings'),
  autoConfigureReceipt: () => request<ReceiptSettings>('/api/receipt/settings/auto', { method: 'POST' }),
  saveReceiptSettings: (body: { evidence_hmac_key: string; attacker_image: string }) =>
    request<ReceiptSettings>('/api/receipt/settings', { method: 'PUT', body: JSON.stringify(body) }),
  providers: () => request<Provider[]>('/api/providers'),
  modelPrices: () => request<ModelPrice[]>('/api/model-prices'),
  saveModelPrices: (models: ModelPrice[]) => request<ModelPrice[]>('/api/model-prices', { method: 'PUT', body: JSON.stringify({ models }) }),
  createProvider: (body: unknown) => request<Provider>('/api/providers', { method: 'POST', body: JSON.stringify(body) }),
  updateProvider: (id: string, body: unknown) =>
    request<Provider>(`/api/providers/${id}`, { method: 'PUT', body: JSON.stringify(body) }),
  deleteProvider: (id: string) => request<{ ok: boolean }>(`/api/providers/${id}`, { method: 'DELETE' }),
  savePrices: (id: string, models: ModelPrice[]) =>
    request<Provider>(`/api/providers/${id}/prices`, { method: 'PUT', body: JSON.stringify({ models }) }),
  saveCatalog: (id: string, models: RemoteModel[]) =>
    request<Provider>(`/api/providers/${id}/catalog`, { method: 'PUT', body: JSON.stringify({ models }) }),
  probeProvider: (body: { provider_id?: string; base_url?: string; api_key?: string }) =>
    request<ProbeResult>('/api/providers/probe', { method: 'POST', body: JSON.stringify(body) }),
  tasks: () => request<AuditTask[]>('/api/tasks'),
  projects: () => request<Project[]>('/api/projects'),
  createProject: (body: FormData) => request<Project>('/api/projects', { method: 'POST', body }),
  initializeProject: (id: string, body: FormData) => request<Project>(`/api/projects/${id}/initialize`, { method: 'POST', body }),
  pauseProjectInitialization: (id: string) => request<Project>(`/api/projects/${id}/initialization/pause`, { method: 'POST' }),
  stopProjectInitialization: (id: string) => request<Project>(`/api/projects/${id}/initialization/stop`, { method: 'POST' }),
  resumeProjectInitialization: (id: string) => request<Project>(`/api/projects/${id}/initialization/resume`, { method: 'POST' }),
  acknowledgeThreatModel: (id: string) => request<Project>(`/api/projects/${id}/threat-model/acknowledge`, { method: 'POST' }),
  threatModelRoles: (id: string) => request<{ digest: string; roles: ThreatRole[] }>(`/api/projects/${id}/threat-model/roles`),
  editThreatModelRole: (id: string, role: ThreatRole, digest: string) => request<{ project: Project; digest: string }>(`/api/projects/${id}/threat-model/roles/${encodeURIComponent(role.id)}`, { method: 'PUT', body: JSON.stringify({ digest, disposition: role.disposition, reason: role.reason, evidence_kind: role.evidence.kind, evidence_path: role.evidence.path, evidence_literal: role.evidence.literal }) }),
  deleteProject: (id: string) => request<{ ok: boolean }>(`/api/projects/${id}`, { method: 'DELETE' }),
  deleteTask: (id: string) => request<{ ok: boolean }>(`/api/tasks/${id}`, { method: 'DELETE' }),
  olderProjectEvents: (id: string, before: number) => request<{ events: LogEvent[]; has_more: boolean }>(`/api/projects/${id}/events/older?before=${before}&limit=100`),
  projectEnvironmentFiles: (id: string) => request<{ files: string[] }>(`/api/projects/${id}/environment`),
  projectEnvironmentContent: (id: string, path: string) => request<{ path: string; content: string }>(`/api/projects/${id}/environment/content?path=${encodeURIComponent(path)}`),
  task: (id: string) => request<AuditTask>(`/api/tasks/${id}`),
  receiptManifests: () => request<ReceiptManifest[]>('/api/receipt/manifests'),
  createTask: (body: FormData) => request<AuditTask>('/api/tasks', { method: 'POST', body }),
  prepareTask: (id: string) => request<AuditTask>(`/api/tasks/${id}/prepare`, { method: 'POST' }),
  checkTask: (id: string, manifest: string) => { const body = new FormData(); body.append('receipt_manifest', manifest); return request<EnvironmentCheck>(`/api/tasks/${id}/check`, { method: 'POST', body }) },
  startTask: (id: string) => request<AuditTask>(`/api/tasks/${id}/start`, { method: 'POST' }),
  pauseTask: (id: string) => request<AuditTask>(`/api/tasks/${id}/pause`, { method: 'POST' }),
  stopTask: (id: string) => request<AuditTask>(`/api/tasks/${id}/stop`, { method: 'POST' }),
  resumeTask: (id: string) => request<AuditTask>(`/api/tasks/${id}/resume`, { method: 'POST' }),
  followUpTask: (id: string, body: { instruction: string; budget: number; duration_minutes: number }) => request<AuditTask>(`/api/tasks/${id}/follow-up`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
  reviewPendingTask: (id: string, body: { budget: number; duration_minutes: number }) => request<AuditTask>(`/api/tasks/${id}/review-pending`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
  reviewAllTask: (id: string, body: { budget: number; duration_minutes: number }) => request<AuditTask>(`/api/tasks/${id}/review-all`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
  reports: (id: string) => request<{ reports: Report[] }>(`/api/tasks/${id}/reports`),
  saveHumanReview: (id: string, path: string, review: HumanReview) => request<HumanReview>(`/api/tasks/${id}/reports/human-review`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ path, ...review }) }),
  artifact: (id: string, path: string) =>
    request<{ path: string; content: string }>(`/api/tasks/${id}/artifacts/content?path=${encodeURIComponent(path)}`),
  olderEvents: (id: string, before: number) =>
    request<{ events: LogEvent[]; has_more: boolean }>(`/api/tasks/${id}/events/older?before=${before}&limit=100`),
}
