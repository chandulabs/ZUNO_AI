import { useState, useEffect, useRef, useCallback } from 'react'
import { Menu, Shield, Brain } from 'lucide-react'
import Sidebar, { NAV } from './components/Sidebar'
import CommandCenter from './components/CommandCenter'
import UrlScanner from './components/UrlScanner'
import ApkLab from './components/ApkLab'
import ThreatIntel from './components/ThreatIntel'
import Explain from './components/Explain'
import Reports from './components/Reports'
import Workflow from './Workflow'
import { Block } from './components/ui'
import { api, newScanId } from './api'
import { Workflow as WF } from 'lucide-react'

export default function App() {
  const [health, setHealth] = useState<any>(null), [stats, setStats] = useState<any>(null)
  const [result, setResult] = useState<any>(null)        // currently selected scan (drives Threat Intel + Explainability + Workflow)
  const [live, setLive] = useState<any>(null)            // real backend processing states of the running scan
  const [refresh, setRefresh] = useState(0)
  const [active, setActive] = useState('command')
  const [collapsed, setCollapsed] = useState(false), [open, setOpen] = useState(false)
  const [pdf, setPdf] = useState<Record<string, string>>({})
  const poll = useRef<any>(null), pidRef = useRef('')

  const loadHealth = useCallback(() => api('/api/health').then(setHealth).catch(() => setHealth(null)), [])
  const loadStats = useCallback(() => api('/api/stats').then(setStats).catch(() => setStats(null)), [])
  useEffect(() => { loadHealth(); loadStats(); const t = setInterval(loadHealth, 15000); return () => clearInterval(t) }, [loadHealth, loadStats])

  // sidebar highlight follows scroll position
  useEffect(() => {
    const els = NAV.map(n => document.getElementById(n.id)).filter(Boolean) as HTMLElement[]
    const io = new IntersectionObserver(es => { const v = es.filter(e => e.isIntersecting).sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0]; if (v) setActive(v.target.id) },
      { rootMargin: '-35% 0px -55% 0px', threshold: [0, 0.1, 0.5] })
    els.forEach(e => io.observe(e)); return () => io.disconnect()
  }, [])
  const goto = (id: string) => { setActive(id); document.getElementById(id)?.scrollIntoView({ behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' }) }

  // live progress polling (real states reported by the backend for the running scan)
  const begin = (mode: string) => {
    const pid = newScanId(); pidRef.current = pid; clearInterval(poll.current)
    setLive({ mode, stages: {}, done: false, verdict: null })
    poll.current = setInterval(async () => { try { const p = await api(`/api/progress/${pid}`); if (pidRef.current === pid) setLive(p) } catch { /* not registered yet */ } }, 250)
    return pid
  }
  const end = async () => {
    clearInterval(poll.current)
    try { const p = await api(`/api/progress/${pidRef.current}`); setLive(p) } catch { setLive(null) }
  }
  const onResult = (r: any) => { setResult(r); loadStats(); loadHealth(); setRefresh(x => x + 1) }
  const openScan = async (id: string) => { try { const r = await api(`/api/scan/${id}`); setLive(null); setResult(r); goto(r.kind === 'apk' ? 'apk' : 'scanner') } catch { /* ignore */ } }
  const loadResult = (r: any) => { setLive(null); setResult(r); goto(r.kind === 'apk' ? 'apk' : 'scanner') }

  const downloadPdf = async (id: string) => {
    setPdf(p => ({ ...p, [id]: 'busy' }))
    try {
      const r = await fetch(`/api/report/${id}/pdf`); if (!r.ok) throw new Error('PDF failed')
      const url = URL.createObjectURL(await r.blob()); const a = document.createElement('a'); a.href = url; a.download = `phishguard-report-${id.slice(0, 8)}.pdf`; a.click(); setTimeout(() => URL.revokeObjectURL(url), 5000)
      setPdf(p => ({ ...p, [id]: 'done' })); setTimeout(() => setPdf(p => { const n = { ...p }; delete n[id]; return n }), 2500)
    } catch { setPdf(p => { const n = { ...p }; delete n[id]; return n }) }
  }

  return (
    <div className={'app' + (collapsed ? ' c' : '')}>
      <Sidebar active={active} onGo={goto} collapsed={collapsed} setCollapsed={setCollapsed} open={open} setOpen={setOpen} online={!!health} />
      <div className="mobile-bar"><button className="icon-btn" onClick={() => setOpen(true)} aria-label="Open menu"><Menu size={20} /></button><Shield size={18} /><b>ZUNO</b></div>
      <main className="main">
        <div className="dash">
          <div className="a-cmd"><CommandCenter health={health} stats={stats} onOpen={openScan} /></div>
          <div className="a-scan"><UrlScanner begin={begin} end={end} live={live} result={result} onResult={onResult} goto={goto} /></div>
          <div className="a-apk"><ApkLab begin={begin} end={end} live={live} result={result} onResult={onResult} maxMb={health?.max_apk_mb || 100} onPdf={downloadPdf} /></div>
          <div className="a-wf">
            <Block id="workflow" title="Detection Workflow" sub="Interactive pipeline — live during real scans" icon={<WF size={20} />} className="wfblock" right={<span className="badge-main">MAIN FEATURE</span>}>
              <Workflow live={live} result={result} />
            </Block>
          </div>
          <div className="a-ti"><ThreatIntel result={result} health={health} /></div>
          <div className="a-end">
            <section className="block end">
              <header className="block-h"><div className="block-ic"><Brain size={20} /></div><div className="block-t"><h2>AI Explainability &amp; Reports</h2><p>SHAP explanations · feature importance · scan history · PDF export</p></div></header>
              <Explain result={result} refreshKey={refresh} />
              <Reports refreshKey={refresh} onLoad={loadResult} onPdf={downloadPdf} pdfState={pdf} />
            </section>
          </div>
        </div>
      </main>
    </div>
  )
}
