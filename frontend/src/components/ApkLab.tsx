import { useRef, useState } from 'react'
import { Smartphone, UploadCloud, Loader2, ChevronDown, FileDown } from 'lucide-react'
import { Block, VerdictTag, Meter, StatusBadge } from './ui'
import { api, VERDICT_COLOR } from '../api'

const LABEL: any = { input: 'Receiving file', validation: 'Validating APK', router: 'Routing', analysis: 'Static analysis (manifest, permissions, strings)', ti: 'Hash lookup', ml: '', shap: '', risk: 'Assessing risk', verdict: 'Final verdict', report: 'Saving report' }

export default function ApkLab({ begin, end, live, result, onResult, maxMb, onPdf }: any) {
  const [drag, setDrag] = useState(false), [busy, setBusy] = useState(false), [err, setErr] = useState(''), [showP, setShowP] = useState(false), [name, setName] = useState('')
  const inp = useRef<HTMLInputElement>(null)
  const r = result?.kind === 'apk' ? result : null
  const send = async (f: File) => {
    setErr('')
    if (!f.name.toLowerCase().endsWith('.apk')) return setErr('Only .apk files are accepted.')
    if (f.size === 0) return setErr('The file is empty.')
    if (f.size > maxMb * 1048576) return setErr(`File is too large (max ${maxMb} MB).`)
    setName(f.name); setBusy(true); const pid = begin('apk')
    try { const d = new FormData(); d.append('file', f); onResult(await api(`/api/scan/apk?scan_id=${pid}`, { method: 'POST', body: d })) }
    catch (x: any) { setErr(x.message) } finally { setBusy(false); end() }
  }
  const cur = live?.mode === 'apk' ? Object.keys(live.stages).find(s => live.stages[s] === 'active') : null
  return (
    <Block id="apk" title="Android APK Lab" sub="Static analysis only — APKs are never executed" icon={<Smartphone size={20} />} className="apk">
      <div className={'drop' + (drag ? ' over' : '') + (busy ? ' busy' : '')} onClick={() => !busy && inp.current?.click()} role="button" tabIndex={0}
        onKeyDown={e => (e.key === 'Enter' || e.key === ' ') && inp.current?.click()}
        onDragOver={e => { e.preventDefault(); setDrag(true) }} onDragLeave={() => setDrag(false)}
        onDrop={e => { e.preventDefault(); setDrag(false); const f = e.dataTransfer.files?.[0]; if (f && !busy) send(f) }}>
        {busy ? <Loader2 size={30} className="spin" /> : <UploadCloud size={30} className="bob" />}
        <b>{busy ? `Analysing ${name}…` : 'Drag & drop an APK here, or click to browse'}</b>
        <small>{busy ? (cur ? LABEL[cur] : 'Uploading…') : `.apk up to ${maxMb} MB · validated on the server (ZIP + AndroidManifest)`}</small>
        {busy && <div className="prog indet"><div /></div>}
        <input ref={inp} type="file" accept=".apk" hidden onChange={e => { const f = e.target.files?.[0]; if (f) send(f); e.target.value = '' }} />
      </div>
      {err && <div className="alert bad" role="alert">{err}</div>}
      {!r && !busy && <div className="empty">Upload an APK to see its metadata, manifest permissions, suspicious permissions, embedded domains/IPs and risk classification.</div>}
      {r && !busy && (() => {
        const c = VERDICT_COLOR[r.verdict], sr = r.static_risk || {}, risk = r.risk || {}
        return <div className="result fade-in" style={{ ['--c' as any]: c }}>
          <div className="verdict-row">
            <div><div className="muted sm">Final risk classification</div><VerdictTag v={r.verdict} big /><span className={'tag sm ' + (sr.level === 'HIGH' ? 'bad' : sr.level === 'MEDIUM' ? 'warn' : 'ok')} style={{ marginLeft: 8 }}>{sr.level} static risk</span></div>
            <div className="grow"><div className="muted sm">Risk score · confidence {risk.confidence}</div><Meter score={risk.score ?? 0} color={c} /></div>
          </div>
          {(risk.notes || []).map((n: string) => <p className="hint" key={n}>{n}</p>)}
          <div className="kv">
            <div><span>App</span><b>{r.app_name || '—'}</b></div><div><span>Package</span><b>{r.package}</b></div><div><span>Version</span><b>{r.version || '—'}</b></div>
            <div><span>Min / target SDK</span><b>{r.min_sdk ?? '—'} / {r.target_sdk ?? '—'}</b></div>
            <div><span>Components</span><b>{r.activities} act · {r.services} svc · {r.receivers} rcv</b></div>
            <div><span>Signed</span><b>{r.signed ? 'Yes' : 'No / unreadable'}</b></div>
            <div className="wide"><span>SHA-256</span><b className="mono">{r.hashes?.sha256}</b></div>
          </div>
          <div className="panel"><h4>Suspicious permissions ({r.risky_permissions?.length || 0})</h4>
            {r.risky_permission_details?.length ? <ul className="ind">{r.risky_permission_details.map((p: any) => <li key={p.permission}><span><b>{p.permission.split('.').pop()}</b><br /><small className="muted">{p.explanation}</small></span></li>)}</ul> : <div className="muted sm">None of the monitored high-risk permissions were requested.</div>}
            <button className="toggle" onClick={() => setShowP(!showP)}>All {r.permissions?.length} manifest permissions <ChevronDown size={14} className={showP ? 'rot' : ''} /></button>
            {showP && <div className="chips">{r.permissions.map((p: string) => <code key={p}>{p.split('.').pop()}</code>)}</div>}
          </div>
          <div className="two">
            <div className="panel"><h4>Extracted domains ({r.domains?.length || 0})</h4>{r.domains?.length ? <div className="chips scroll">{r.domains.slice(0, 60).map((d: string) => <code key={d}>{d}</code>)}</div> : <div className="muted sm">None found.</div>}</div>
            <div className="panel"><h4>IP addresses ({r.ips?.length || 0})</h4>{r.ips?.length ? <div className="chips">{r.ips.map((d: string) => <code className="hot" key={d}>{d}</code>)}</div> : <div className="muted sm">None found.</div>}</div>
          </div>
          <div className="panel"><h4>Risk indicators</h4>{sr.indicators?.length ? <ul className="ind">{sr.indicators.map((i: any) => <li key={i.indicator}><span>{i.indicator}<br /><small className="muted">{i.detail}</small></span><b>+{i.weight}</b></li>)}</ul> : <div className="muted sm">No static indicators found.</div>}
            <div className="ti-row"><span>Local Threat Intelligence (file hash)</span><StatusBadge s={r.threat_intel?.[0]?.status || 'UNKNOWN'} /></div>
          </div>
          <button className="btn sm" onClick={() => onPdf(r.id)}><FileDown size={14} /> Analysis report (PDF)</button>
        </div>
      })()}
    </Block>
  )
}
