import { useEffect, useState, useCallback } from 'react'
import { FileText, Search, FileDown, Eye, Loader2, CheckCircle2, ArrowUpRight } from 'lucide-react'
import { VerdictTag, StatusBadge } from './ui'
import { api, fmtTime } from '../api'

export default function Reports({ refreshKey, onLoad, onPdf, pdfState }: any) {
  const [q, setQ] = useState(''), [verdict, setVerdict] = useState(''), [kind, setKind] = useState('')
  const [rows, setRows] = useState<any[] | null>(null), [total, setTotal] = useState(0), [err, setErr] = useState('')
  const [detail, setDetail] = useState<any>(null), [loadingId, setLoadingId] = useState('')
  const load = useCallback(async () => {
    try { const p = new URLSearchParams({ limit: '100' }); if (q.trim()) p.set('q', q.trim()); if (verdict) p.set('verdict', verdict); if (kind) p.set('kind', kind)
      const j = await api(`/api/history?${p}`); setRows(j.items); setTotal(j.total); setErr('') } catch (e: any) { setErr(e.message); setRows([]) }
  }, [q, verdict, kind])
  useEffect(() => { const t = setTimeout(load, 250); return () => clearTimeout(t) }, [load, refreshKey])
  const view = async (id: string) => { setLoadingId(id); try { setDetail(await api(`/api/scan/${id}`)) } catch (e: any) { setErr(e.message) } finally { setLoadingId('') } }
  return (
    <div id="reports" className="sub">
      <header className="block-h"><div className="block-ic"><FileText size={20} /></div><div className="block-t"><h2>Reports &amp; History</h2><p>{total} stored scan{total === 1 ? '' : 's'} · search, filter, review and export PDF</p></div></header>
      <div className="filters">
        <div className="search"><Search size={15} /><input value={q} onChange={e => setQ(e.target.value)} placeholder="Search URL or package…" aria-label="Search history" /></div>
        <select value={verdict} onChange={e => setVerdict(e.target.value)} aria-label="Filter by verdict"><option value="">All verdicts</option>{['SAFE', 'SUSPICIOUS', 'PHISHING', 'UNKNOWN'].map(v => <option key={v}>{v}</option>)}</select>
        <select value={kind} onChange={e => setKind(e.target.value)} aria-label="Filter by type"><option value="">URL + APK</option><option value="url">URL</option><option value="apk">APK</option></select>
      </div>
      {err && <div className="alert bad">{err}</div>}
      <div className="tbl-wrap">
        <table className="tbl hist"><thead><tr><th>Time</th><th>Type</th><th>Target</th><th>Verdict</th><th>Risk</th><th /></tr></thead>
          <tbody>
            {rows === null && <tr><td colSpan={6}><div className="skeleton" /></td></tr>}
            {rows?.length === 0 && <tr><td colSpan={6} className="muted">No scans match.</td></tr>}
            {rows?.map((x, i) => (
              <tr key={x.id} className="row-in" style={{ animationDelay: `${Math.min(i, 12) * 25}ms` }}>
                <td>{fmtTime(x.created)}</td><td><span className="k">{x.kind.toUpperCase()}</span></td><td className="trunc" title={x.target}>{x.target}</td>
                <td><VerdictTag v={x.verdict} /></td><td>{x.score ?? '—'}</td>
                <td className="acts">
                  <button className="icon-btn" title="View details" onClick={() => view(x.id)}>{loadingId === x.id ? <Loader2 size={16} className="spin" /> : <Eye size={16} />}</button>
                  <button className="icon-btn" title="Download PDF report" onClick={() => onPdf(x.id)}>{pdfState[x.id] === 'busy' ? <Loader2 size={16} className="spin" /> : pdfState[x.id] === 'done' ? <CheckCircle2 size={16} className="okc" /> : <FileDown size={16} />}</button>
                </td></tr>))}
          </tbody></table>
      </div>
      {Object.values(pdfState).includes('busy') && <div className="alert info"><Loader2 size={14} className="spin" /> Generating PDF report…</div>}
      {detail && <div className="panel detail fade-in">
        <div className="detail-h"><h4>Scan details</h4><div><button className="btn sm ghost" onClick={() => onLoad(detail)}><ArrowUpRight size={14} /> Load into dashboard</button> <button className="btn sm" onClick={() => onPdf(detail.id)}><FileDown size={14} /> PDF</button> <button className="icon-btn" onClick={() => setDetail(null)} aria-label="Close">×</button></div></div>
        <div className="kv small"><div className="wide"><span>{detail.kind === 'url' ? 'URL' : 'Package'}</span><b className="mono">{detail.url || detail.package}</b></div>
          <div><span>Verdict</span><b><VerdictTag v={detail.verdict} /></b></div><div><span>Risk score</span><b>{detail.risk?.score ?? '—'}/100</b></div><div><span>Scanned</span><b>{fmtTime(detail.created)}</b></div>
          {detail.ml && <div><span>ML probability</span><b>{detail.ml.available ? (detail.ml.probability * 100).toFixed(1) + '%' : 'ML MODEL NOT AVAILABLE'}</b></div>}
          {detail.kind === 'url' && <div><span>SHAP</span><b>{detail.shap?.available ? 'Available' : 'Not available'}</b></div>}</div>
        <div className="chips">{(detail.threat_intel || []).map((t: any) => <span key={t.source} className="ti-chip">{t.source} <StatusBadge s={t.status} /></span>)}</div>
        {detail.rules?.triggered?.length > 0 && <><h4>Indicators</h4><ul className="ind">{detail.rules.triggered.map((t: any) => <li key={t.id}><span>{t.label}</span><b>+{t.weight}</b></li>)}</ul></>}
        {detail.static_risk?.indicators?.length > 0 && <><h4>APK indicators</h4><ul className="ind">{detail.static_risk.indicators.map((t: any) => <li key={t.indicator}><span>{t.indicator}</span><b>+{t.weight}</b></li>)}</ul></>}
        {detail.risk?.breakdown && <><h4>Risk breakdown</h4><ul className="ind">{detail.risk.breakdown.map((b: any) => <li key={b.source}><span>{b.source}<br /><small className="muted">{b.detail}</small></span><b>{b.value ?? 'n/a'}</b></li>)}</ul></>}
      </div>}
    </div>
  )
}
