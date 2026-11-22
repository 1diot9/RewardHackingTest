import { useEffect, useState } from 'react'
import { api, type ModelPrice, type Provider, type ReceiptSettings, type RemoteModel } from '@/api'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'

type Endpoint = { id?: string; name: string; base_url: string; api_key: string; model: string; key_hint: string; availableModels: RemoteModel[]; fetchMessage: string }
type Price = { id: string; currency: string; input: string; output: string; read: string; write: string }
const endpointFrom = (p: Provider): Endpoint => ({ id: p.id, name: p.name, base_url: p.base_url, api_key: '', model: p.model || p.models[0]?.id || '', key_hint: p.key_hint, availableModels: [], fetchMessage: '' })
const priceFrom = (p: ModelPrice): Price => ({ id: p.id, currency: p.currency || 'USD', input: String(p.input_per_mtok), output: String(p.output_per_mtok), read: p.cache_read_per_mtok == null ? '' : String(p.cache_read_per_mtok), write: p.cache_write_per_mtok == null ? '' : String(p.cache_write_per_mtok) })

export default function SettingsPage() {
  const [endpoints, setEndpoints] = useState<Endpoint[]>([])
  const [prices, setPrices] = useState<Price[]>([])
  const [receipt, setReceipt] = useState<ReceiptSettings | null>(null)
  const [concurrency, setConcurrency] = useState('')
  const [proxy, setProxy] = useState({ enabled: false, url: '', no_proxy: '' })
  const [evidenceHmacKey, setEvidenceHmacKey] = useState('')
  const [attackerImage, setAttackerImage] = useState('')
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState(false)
  const [configuringReceipt, setConfiguringReceipt] = useState(false)
  useEffect(() => { Promise.all([api.providers(), api.modelPrices(), api.receiptSettings(), api.concurrencySettings(), api.proxySettings()]).then(([providers, items, receiptSettings, concurrencySettings, proxySettings]) => { setEndpoints(providers.map(endpointFrom)); setPrices(items.map(priceFrom)); setReceipt(receiptSettings); setAttackerImage(receiptSettings.attacker_image); setConcurrency(String(concurrencySettings.max_concurrent)); setProxy(proxySettings) }).catch((e: Error) => setError(e.message)) }, [])
  const updateEndpoint = (index: number, patch: Partial<Endpoint>) => setEndpoints((rows) => rows.map((row, i) => i === index ? { ...row, ...((patch.base_url !== undefined && patch.base_url !== row.base_url) || (patch.api_key !== undefined && patch.api_key !== row.api_key) ? { model: '', availableModels: [], fetchMessage: '' } : {}), ...patch } : row))
  const updatePrice = (index: number, patch: Partial<Price>) => setPrices((rows) => rows.map((row, i) => i === index ? { ...row, ...patch } : row))
  async function saveEndpoint(row: Endpoint, index: number) {
    setBusy(true); setError(''); setNotice('')
    try {
      if (!row.name.trim() || !row.base_url.trim() || !row.model.trim() || (!row.id && !row.api_key.trim())) throw new Error('请填写端点名称、Base URL 和 API Key，并从模型列表中选择模型')
      const result = row.id ? await api.updateProvider(row.id, row) : await api.createProvider(row)
      setEndpoints((rows) => rows.map((item, i) => i === index ? { ...endpointFrom(result), availableModels: item.availableModels, fetchMessage: item.fetchMessage } : item)); setNotice('端点已保存')
    } catch (e) { setError(e instanceof Error ? e.message : '保存失败') } finally { setBusy(false) }
  }
  async function fetchModels(row: Endpoint, index: number) {
    setBusy(true); setError(''); setNotice('')
    updateEndpoint(index, { availableModels: [], fetchMessage: '' })
    try {
      if (!row.base_url.trim()) throw new Error('请先填写 Base URL')
      const result = await api.probeProvider({ provider_id: row.id, base_url: row.base_url, api_key: row.api_key })
      if (!result.ok) throw new Error(result.message)
      setEndpoints((rows) => rows.map((item, i) => i === index && item.base_url === row.base_url && item.api_key === row.api_key ? { ...item, availableModels: result.models, fetchMessage: result.message } : item))
    } catch (e) { setError(e instanceof Error ? e.message : '拉取模型列表失败') } finally { setBusy(false) }
  }
  async function removeEndpoint(row: Endpoint, index: number) {
    if (row.id && !window.confirm(`删除端点「${row.name}」？`)) return
    setBusy(true); setError('')
    try { if (row.id) await api.deleteProvider(row.id); setEndpoints((rows) => rows.filter((_, i) => i !== index)) } catch (e) { setError(e instanceof Error ? e.message : '删除失败') } finally { setBusy(false) }
  }
  async function savePrices() {
    setBusy(true); setError(''); setNotice('')
    try {
      const models = prices.map((p) => {
        if (!p.id.trim() || !p.input.trim() || !p.output.trim() || [p.input, p.output, p.read, p.write].some((v) => v.trim() && (!Number.isFinite(Number(v)) || Number(v) < 0))) throw new Error('请填写模型名称和有效的非负单价')
        return { id: p.id.trim(), name: p.id.trim(), currency: p.currency, input_per_mtok: Number(p.input), output_per_mtok: Number(p.output), cache_read_per_mtok: p.read.trim() ? Number(p.read) : null, cache_write_per_mtok: p.write.trim() ? Number(p.write) : null }
      })
      setPrices((await api.saveModelPrices(models)).map(priceFrom)); setNotice('模型定价已保存')
    } catch (e) { setError(e instanceof Error ? e.message : '保存失败') } finally { setBusy(false) }
  }
  async function saveReceiptSettings() {
    setBusy(true); setError(''); setNotice('')
    try {
      const result = await api.saveReceiptSettings({ evidence_hmac_key: evidenceHmacKey, attacker_image: attackerImage })
      setReceipt(result); setEvidenceHmacKey(''); setAttackerImage(result.attacker_image); setNotice('RECEIPT 设置已保存')
    } catch (e) { setError(e instanceof Error ? e.message : '保存失败') } finally { setBusy(false) }
  }
  async function saveConcurrency() {
    setBusy(true); setError(''); setNotice('')
    try {
      const value = Number(concurrency)
      if (!/^\d+$/.test(concurrency) || !Number.isSafeInteger(value) || value < 1) throw new Error('并发数量必须是大于等于 1 的整数')
      const result = await api.saveConcurrencySettings(value)
      setConcurrency(String(result.max_concurrent)); setNotice('并发数量已保存并生效')
    } catch (e) { setError(e instanceof Error ? e.message : '保存失败') } finally { setBusy(false) }
  }
  async function saveProxy() {
    setBusy(true); setError(''); setNotice('')
    try { setProxy(await api.saveProxySettings(proxy)); setNotice('代理设置已保存，将用于新启动的初始化 Agent') }
    catch (e) { setError(e instanceof Error ? e.message : '保存失败') } finally { setBusy(false) }
  }
  async function autoConfigureReceipt() {
    if (evidenceHmacKey || attackerImage !== (receipt?.attacker_image || '')) {
      setError('请先保存或清除尚未保存的 RECEIPT 设置'); setNotice(''); return
    }
    setBusy(true); setConfiguringReceipt(true); setError(''); setNotice('')
    try {
      const result = await api.autoConfigureReceipt()
      setReceipt(result); setAttackerImage(result.attacker_image); setNotice('RECEIPT 自动配置完成')
    } catch (e) { setError(e instanceof Error ? e.message : '自动配置失败') } finally { setBusy(false); setConfiguringReceipt(false) }
  }
  return <div className="flex flex-col gap-8">
    <section className="grid gap-4">
      <div><h2 className="text-xl font-semibold">初始化网络代理</h2><p className="text-sm text-muted-foreground">供新启动的环境初始化 Agent 使用；Docker 拉取镜像和容器网络需单独配置。localhost、127.0.0.1、::1 和已知靶场地址自动直连；其他内网地址可自行添加。工具是否使用代理取决于其实现。</p></div>
      <Card><CardContent className="grid gap-4 pt-6">
        <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={proxy.enabled} onChange={(e) => setProxy({ ...proxy, enabled: e.target.checked })} />启用代理</label>
        <Field label="HTTP/HTTPS 代理地址" value={proxy.url} placeholder="http://127.0.0.1:7890" onChange={(url) => setProxy({ ...proxy, url })} />
        <Field label="额外直连地址（逗号分隔）" value={proxy.no_proxy} placeholder="example.internal,192.168.1.10" onChange={(no_proxy) => setProxy({ ...proxy, no_proxy })} />
      </CardContent><CardFooter><Button disabled={busy} onClick={() => void saveProxy()}>保存代理设置</Button></CardFooter></Card>
    </section>
    <section className="grid gap-4">
      <div><h2 className="text-xl font-semibold">审计并发</h2><p className="text-sm text-muted-foreground">所有项目共享此上限。提高后等待中的任务可立即启动；降低后运行中的任务继续执行，直至数量低于新上限。</p></div>
      <Card><CardContent className="grid max-w-xs gap-4 pt-6"><Field label="最大并发任务数" type="number" value={concurrency} onChange={setConcurrency} /></CardContent><CardFooter><Button disabled={busy || !concurrency} onClick={() => void saveConcurrency()}>保存并发设置</Button></CardFooter></Card>
    </section>
    <section className="grid gap-4">
      <div className="flex items-center justify-between"><div><h1 className="text-xl font-semibold">LLM 端点</h1><p className="text-sm text-muted-foreground">配置连接，从拉取的列表中选择模型。</p></div><Button disabled={busy} onClick={() => setEndpoints((rows) => [{ name: '', base_url: '', api_key: '', model: '', key_hint: '', availableModels: [], fetchMessage: '' }, ...rows])}>添加端点</Button></div>
      {error && <p className="text-sm text-destructive">{error}</p>}{notice && <p className="text-sm text-emerald-300">{notice}</p>}
      {endpoints.map((row, i) => <Card key={row.id || `new-${i}`}><CardHeader><CardTitle>{row.name || '新端点'}</CardTitle></CardHeader><CardContent className="grid gap-3 sm:grid-cols-2">
        <Field label="自定义名称" value={row.name} onChange={(v) => updateEndpoint(i, { name: v })} />
        <Field label="Base URL" value={row.base_url} onChange={(v) => updateEndpoint(i, { base_url: v })} />
        <Field label="API Key" type="password" placeholder={row.id ? `留空则不修改 ${row.key_hint}` : ''} value={row.api_key} onChange={(v) => updateEndpoint(i, { api_key: v })} />
        <div className="grid gap-1.5"><Label>使用的模型</Label><Select value={row.model} disabled={busy || row.availableModels.length === 0} onValueChange={(value) => { if (value) updateEndpoint(i, { model: value }) }}><SelectTrigger><SelectValue placeholder="请先拉取模型列表">{row.model ? (row.availableModels.find((model) => model.id === row.model)?.name || row.model) : '请先拉取模型列表'}</SelectValue></SelectTrigger><SelectContent>{row.model && !row.availableModels.some((model) => model.id === row.model) && <SelectItem value={row.model} disabled>{row.model}（已保存）</SelectItem>}{row.availableModels.map((model) => <SelectItem key={model.id} value={model.id}>{model.name && model.name !== model.id ? `${model.name}（${model.id}）` : model.id}</SelectItem>)}</SelectContent></Select></div>
        {row.fetchMessage && <p className="self-end text-sm text-muted-foreground">{row.fetchMessage}</p>}
      </CardContent><CardFooter className="flex-wrap gap-2"><Button disabled={busy} onClick={() => void saveEndpoint(row, i)}>保存端点</Button><Button variant="outline" disabled={busy} onClick={() => void fetchModels(row, i)}>拉取模型列表</Button><Button variant="destructive" disabled={busy} onClick={() => void removeEndpoint(row, i)}>删除</Button></CardFooter></Card>)}
    </section>
    <section className="grid gap-4">
      <div><h2 className="text-xl font-semibold">RECEIPT 验证器</h2><p className="text-sm text-muted-foreground">证据签名密钥用于保护已落盘的验证结果；攻击者镜像必须使用不可变的 sha256 digest，在隔离容器中运行 PoC。</p></div>
      <Card><CardContent className="grid gap-4 pt-6">
        {receipt && <div className={`rounded-md border px-3 py-2 text-sm ${receipt.ready ? 'border-emerald-500/40 text-emerald-300' : 'border-destructive/40 text-destructive'}`}>
          {receipt.ready ? '配置已就绪。' : `配置未完成：${receipt.issues.join('；')}`}
        </div>}
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="证据签名密钥" type="password" value={evidenceHmacKey} placeholder={receipt?.has_evidence_hmac_key ? `已配置 ${receipt.evidence_hmac_key_hint}；留空则不修改` : '请输入独立的随机密钥'} onChange={setEvidenceHmacKey} />
          <div className="grid gap-1.5"><Label>当前密钥来源</Label><p className="rounded-md border border-input px-3 py-2 text-sm text-muted-foreground">{receipt?.evidence_hmac_key_source === 'settings' ? '本地设置' : receipt?.evidence_hmac_key_source === 'environment' ? '环境变量' : '未配置'}</p></div>
          <Field label="攻击者镜像" value={attackerImage} placeholder="registry.example/receipt-python@sha256:…" onChange={setAttackerImage} />
          <div className="grid gap-1.5"><Label>镜像来源</Label><p className="rounded-md border border-input px-3 py-2 text-sm text-muted-foreground">{receipt?.attacker_image_source === 'settings' ? '本地设置' : receipt?.attacker_image_source === 'environment' ? '环境变量' : '未配置'}</p></div>
        </div>
      </CardContent><CardFooter className="flex-wrap gap-2"><Button disabled={busy} onClick={() => void saveReceiptSettings()}>保存 RECEIPT 设置</Button><Button variant="outline" disabled={busy || !receipt} onClick={() => void autoConfigureReceipt()}>{configuringReceipt ? '正在准备镜像，请稍候…' : '自动配置'}</Button></CardFooter></Card>
    </section>
    <section className="grid gap-4" id="model-prices"><div><h2 className="text-xl font-semibold">模型定价</h2><p className="text-sm text-muted-foreground">单价按每百万 token 计算。按模型名称精确匹配；未匹配时不计价，预算不会限制费用。缓存单价留空时按输入单价计算。</p></div>
      <Card><CardContent className="grid gap-4 pt-6">{prices.map((p, i) => <div className="grid gap-2 sm:grid-cols-7" key={i}>
        <Field label="模型名称" value={p.id} onChange={(v) => updatePrice(i, { id: v })} />
        <div className="grid gap-1.5"><Label>货币</Label><Select value={p.currency} onValueChange={(v) => updatePrice(i, { currency: v || 'USD' })}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="USD">USD</SelectItem><SelectItem value="CNY">CNY</SelectItem></SelectContent></Select></div>
        <Field label="输入" value={p.input} onChange={(v) => updatePrice(i, { input: v })} /><Field label="输出" value={p.output} onChange={(v) => updatePrice(i, { output: v })} /><Field label="缓存读" value={p.read} onChange={(v) => updatePrice(i, { read: v })} /><Field label="缓存写" value={p.write} onChange={(v) => updatePrice(i, { write: v })} />
        <div className="flex items-end"><Button variant="ghost" onClick={() => setPrices((rows) => rows.filter((_, n) => n !== i))}>移除</Button></div>
      </div>)}<div><Button variant="outline" onClick={() => setPrices((rows) => [...rows, { id: '', currency: 'USD', input: '', output: '', read: '', write: '' }])}>添加模型定价</Button></div></CardContent><CardFooter><Button disabled={busy} onClick={() => void savePrices()}>保存单价</Button></CardFooter></Card>
    </section>
  </div>
}

function Field({ label, value, onChange, placeholder, type = 'text' }: { label: string; value: string; onChange: (value: string) => void; placeholder?: string; type?: string }) {
  return <label className="grid gap-1.5"><span className="text-sm font-medium">{label}</span><Input type={type} value={value} placeholder={placeholder} onChange={(e) => onChange(e.target.value)} /></label>
}
