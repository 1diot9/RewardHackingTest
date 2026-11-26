import { useState } from 'react'
import { api, type Project, type ThreatRole } from '@/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'

export default function ThreatModelEditor({ project, onUpdate }: { project: Project; onUpdate: (project: Project) => void }) {
  const [roles, setRoles] = useState<ThreatRole[]>([])
  const [digest, setDigest] = useState('')
  const [selected, setSelected] = useState('')
  const [draft, setDraft] = useState<ThreatRole | null>(null)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')

  async function load() {
    setBusy(true)
    setMessage('')
    try {
      const result = await api.threatModelRoles(project.id)
      setRoles(result.roles)
      setDigest(result.digest)
      setSelected('')
      setDraft(null)
    } catch (error) { setMessage(error instanceof Error ? error.message : '加载失败') }
    finally { setBusy(false) }
  }

  async function save() {
    if (!draft) return
    setBusy(true)
    setMessage('')
    try {
      const result = await api.editThreatModelRole(project.id, draft, digest)
      onUpdate(result.project)
      setDigest(result.digest)
      setRoles((current) => current.map((role) => role.id === draft.id ? draft : role))
      setMessage('已保存并重新检查；请核实剩余待确认项。')
    } catch (error) { setMessage(error instanceof Error ? error.message : '保存失败') }
    finally { setBusy(false) }
  }

  return <section className="grid gap-3 rounded-lg border p-3 text-sm">
    <h2 className="font-medium">角色处置编辑</h2>
    <p className="text-muted-foreground">修改处置、理由和证据。保存时检查角色、账号与攻击路径的一致性；更改处置可能需要同步调整其他模型材料。源码证据须填写源码相对路径及文件中存在的字面量。</p>
    <div><Button variant="outline" disabled={busy} onClick={() => void load()}>{roles.length ? '重新加载角色' : '加载角色'}</Button></div>
    {roles.length ? <label className="grid gap-1">选择角色<select className="rounded border p-2" value={selected} onChange={(event) => { const id = event.target.value; setSelected(id); setDraft(roles.find((role) => role.id === id) || null); setMessage('') }}><option value="">请选择</option>{roles.map((role) => <option key={role.id} value={role.id}>{role.id}（{role.literal}）</option>)}</select></label> : null}
    {draft ? <>
      <label className="grid gap-1">处置<select className="rounded border p-2" value={draft.disposition} onChange={(event) => setDraft({ ...draft, disposition: event.target.value })}><option value="include">纳入攻击者</option><option value="victim_only">仅作为受害者</option><option value="exclude">排除</option></select></label>
      <label className="grid gap-1">处置理由<Textarea value={draft.reason} onChange={(event) => setDraft({ ...draft, reason: event.target.value })} /></label>
      <label className="grid gap-1">证据类型<select className="rounded border p-2" value={draft.evidence.kind} onChange={(event) => setDraft({ ...draft, evidence: { ...draft.evidence, kind: event.target.value } })}><option value="source">源码</option><option value="official_doc">官方文档</option><option value="historical_advisory">历史公告</option><option value="assumption">假设</option></select></label>
      <label className="grid gap-1">证据路径或位置<Input value={draft.evidence.path} onChange={(event) => setDraft({ ...draft, evidence: { ...draft.evidence, path: event.target.value } })} /></label>
      <label className="grid gap-1">证据字面量<Input value={draft.evidence.literal} onChange={(event) => setDraft({ ...draft, evidence: { ...draft.evidence, literal: event.target.value } })} /></label>
      <div><Button disabled={busy} onClick={() => void save()}>{busy ? '保存中…' : '保存并重新检查'}</Button></div>
    </> : null}
    {message ? <p role="status" className="break-words">{message}</p> : null}
  </section>
}
