import { useState, useRef, useEffect, useMemo, useCallback } from 'react'
import { ReactFlow, ReactFlowProvider, Background, MarkerType, useReactFlow } from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { Maximize2, Minimize2, Play, Check, X, Minus, Link2, Smartphone } from 'lucide-react'
import { VERDICT_COLOR } from './api'

const col: any = { input: '#B8C9AE', valid: '#A2ADA6', url: '#A3E635', apk: '#E9B96E', ti: '#B8C9AE', ml: '#A3E635', xai: '#B8C9AE', risk: '#E9B96E', out: '#8DDB78' }

// id, label, colour key, description, x, y, backend stage it maps to
const N: [string, string, string, string, number, number, string][] = [
  ['input', 'URL / APK Input', 'input', 'The submitted URL or uploaded Android package enters the pipeline.', 0, 0, 'input'],
  ['validation', 'Input Validation', 'valid', 'URL format / scheme / length checks, or APK extension, size, ZIP + AndroidManifest checks. Submitted targets are never visited or executed.', 0, 72, 'validation'],
  ['router', 'Analysis Router', 'valid', 'Routes the input to URL feature extraction or APK static analysis.', 0, 144, 'router'],
  ['url', 'URL Feature Extraction', 'url', 'Lexical features (length, dots, hyphens, entropy, IP host, keywords, TLD, subdomains…) and rule-based indicators.', -150, 236, 'analysis'],
  ['apk', 'APK Static Analysis', 'apk', 'Androguard static parsing: manifest, permissions, embedded URLs/domains, certificates. Never executed.', 150, 236, 'analysis'],
  ['ti', 'Threat Intelligence Lookup', 'ti', 'Local SQLite threat intelligence database & OpenPhish community feed matching. 100% on-premise without external APIs.', 0, 328, 'ti'],
  ['ml', 'Hybrid Machine Learning & DL', 'ml', 'Random Forest, XGBoost & Neural Character-CNN/BiLSTM local inference with hybrid fusion.', 0, 400, 'ml'],
  ['shap', 'SHAP & Neural Explainability', 'xai', 'SHAP TreeExplainer for Random Forest and character-level saliency for neural networks.', 0, 472, 'shap'],
  ['risk', 'Risk Assessment', 'risk', 'Transparent scoring that combines rules, ML, and threat-intel evidence. Missing evidence is not negative evidence.', 0, 544, 'risk'],
  ['verdict', 'Final Verdict', 'out', 'SAFE / SUSPICIOUS / PHISHING / UNKNOWN.', 0, 616, 'verdict'],
  ['report', 'Report Generation', 'out', 'Result stored in history; PDF report available from Reports & History.', 0, 688, 'report'],
]
const E_: [string, string][] = [['input', 'validation'], ['validation', 'router'], ['router', 'url'], ['router', 'apk'], ['url', 'ti'], ['apk', 'ti'], ['ti', 'ml'], ['ml', 'shap'], ['shap', 'risk'], ['risk', 'verdict'], ['verdict', 'report']]
const ORDER = ['input', 'validation', 'router', 'analysis', 'ti', 'ml', 'shap', 'risk', 'verdict', 'report']

type St = 'pending' | 'active' | 'done' | 'skipped' | 'error'

function Inner({ live, result }: { live: any; result: any }) {
  const [sel, setSel] = useState<string | null>(null)
  const [demo, setDemo] = useState(-1)           // index into ORDER while the simulated demonstration runs
  const [full, setFull] = useState(false)
  const [flowType, setFlowType] = useState<'url' | 'apk'>(result?.kind === 'apk' ? 'apk' : 'url')
  const ref = useRef<HTMLDivElement>(null), timer = useRef<any>(null)
  const fitFrame = useRef(0)
  const rf = useReactFlow()
  const scheduleFit = useCallback(() => {
    cancelAnimationFrame(fitFrame.current)
    fitFrame.current = requestAnimationFrame(() => {
      void rf.fitView({ padding: 0.1, duration: 0 }).then(fitted => {
        if (!fitted) return
        const { zoom } = rf.getViewport()
        rf.setCenter(0, 370, { zoom, duration: 220 })
      })
    })
  }, [rf])

  useEffect(() => () => clearInterval(timer.current), [])
  useEffect(() => {
    const canvas = ref.current?.querySelector('.wf-canvas')
    if (!canvas) return
    const observer = new ResizeObserver(scheduleFit)
    observer.observe(canvas)
    return () => {
      observer.disconnect()
      cancelAnimationFrame(fitFrame.current)
    }
  }, [scheduleFit])
  useEffect(() => {
    scheduleFit()
    return () => cancelAnimationFrame(fitFrame.current)
  }, [flowType, scheduleFit])
  useEffect(() => {
    const h = () => { setFull(!!document.fullscreenElement); setTimeout(() => rf.fitView({ padding: 0.15, duration: 300 }), 120) }
    document.addEventListener('fullscreenchange', h); return () => document.removeEventListener('fullscreenchange', h)
  }, [rf])
  useEffect(() => { if (live && !live.done) { clearInterval(timer.current); setDemo(-1) } }, [live])
  useEffect(() => {
    const type = live?.mode || result?.kind
    if (type === 'url' || type === 'apk') setFlowType(type)
  }, [live?.mode, result?.kind])

  const mode: 'demo' | 'live' | 'last' | 'idle' = demo >= 0 ? 'demo'
    : live?.mode === flowType ? 'live'
      : result?.timeline && result.kind === flowType ? 'last' : 'idle'
  const kind = flowType

  const demoStages = useMemo<Record<string, St>>(() => {
    const m: Record<string, St> = {}
    ORDER.forEach(s => (m[s] = 'pending'))
    if (mode === 'demo') ORDER.forEach((s, i) => (m[s] = i < demo ? 'done' : i === demo ? 'active' : 'pending'))
    return m
  }, [mode, demo])

  const verdict: string | null = mode === 'live' ? (live.done ? live.verdict : null) : mode === 'last' ? result.verdict : null
  const ms: Record<string, number> = {}
  if (mode === 'last') (result.timeline || []).forEach((t: any) => (ms[t.stage] = t.ms))

  const actualStages: Record<string, St> = mode === 'live'
    ? (live.stages || {})
    : mode === 'last'
      ? Object.fromEntries((result.timeline || []).map((t: any) => [t.stage, t.status]))
      : {}

  const combinedStatus = (keys: string[]): St => {
    const statuses = keys.map(key => actualStages[key]).filter((status): status is St => !!status && status !== 'pending')
    if (statuses.includes('error')) return 'error'
    if (statuses.includes('active')) return 'active'
    if (!statuses.length) return 'pending'
    if (statuses.every(status => status === 'done' || status === 'skipped')) {
      return statuses.includes('done') ? 'done' : 'skipped'
    }
    return statuses.includes('done') ? 'active' : 'pending'
  }

  const nodeStatus = (n: (typeof N)[number]): St | 'inactive' => {
    if (n[0] === 'url' && kind === 'apk' && mode !== 'demo') return 'inactive'
    if (n[0] === 'apk' && kind !== 'apk' && mode !== 'demo') return 'inactive'
    if (mode === 'demo') return demoStages[n[6]] || 'pending'
    if (mode !== 'live' && mode !== 'last') return 'pending'

    const stages: Record<string, string[]> = {
      router: ['normalization'],
      analysis: ['features', 'rules'],
      ti: ['threat_intel'],
      ml: ['random_forest', 'xgboost', 'active_model', 'ensemble', 'cnn', 'bilstm'],
    }
    return combinedStatus(stages[n[6]] || [n[6]])
  }

  const nodes = N.map(n => {
    const s = nodeStatus(n), c = col[n[2]]
    const active = s === 'active', done = s === 'done'
    const bg = s === 'inactive' ? '#0b1020' : active ? c + 'cc' : done ? c + '55' : s === 'error' ? '#ef444466' : s === 'skipped' ? '#1e293b' : c + '1f'
    const label = n[0] === 'input' ? (flowType === 'url' ? 'URL Input' : 'APK File Input')
      : n[0] === 'verdict' && verdict ? `Final Verdict: ${verdict}` : n[1]
    const icon = done ? <Check size={13} /> : s === 'error' ? <X size={13} /> : s === 'skipped' ? <Minus size={13} /> : null
    return {
      id: n[0], position: { x: n[4] - 110, y: n[5] },
      className: active ? 'wf-active' : '',
      data: { label: <div className="wfn">{icon}<span>{label}</span>{ms[n[6]] != null && s !== 'skipped' && <small>{ms[n[6]]} ms</small>}{s === 'skipped' && <small>not run</small>}</div> },
      style: {
        background: bg, color: '#fff', borderRadius: 12, padding: 8, width: 220, fontSize: 13,
        border: `2px ${s === 'skipped' || s === 'inactive' ? 'dashed' : 'solid'} ${s === 'error' ? '#ef4444' : s === 'inactive' ? '#334155' : c}`,
        opacity: s === 'inactive' ? 0.45 : 1,
        boxShadow: active ? `0 0 26px ${c}` : n[0] === 'verdict' && verdict ? `0 0 22px ${VERDICT_COLOR[verdict]}88` : 'none',
        borderColor: n[0] === 'verdict' && verdict ? VERDICT_COLOR[verdict] : undefined,
      },
    }
  })
  const edges = E_.map(([s, t]) => {
    const tn = N.find(x => x[0] === t)!, sn = N.find(x => x[0] === s)!
    const ts = nodeStatus(tn), ss = nodeStatus(sn)
    const dead = ts === 'inactive' || ss === 'inactive'
    const flowing = ts === 'active' || (mode === 'demo' && ss === 'done' && ts !== 'done')
    return { id: s + t, source: s, target: t, animated: flowing || mode === 'idle', markerEnd: { type: MarkerType.ArrowClosed, color: dead ? '#35423C' : '#A3E635' },
      style: { stroke: dead ? '#35423C' : ss === 'done' ? '#B8C9AE' : '#A3E635', strokeWidth: ss === 'done' ? 2.5 : 1.5, strokeDasharray: dead ? '4 4' : undefined } }
  })

  const run = () => {
    clearInterval(timer.current); let i = 0; setDemo(0)
    timer.current = setInterval(() => { i++; if (i >= ORDER.length) { clearInterval(timer.current); setTimeout(() => setDemo(-1), 900) } else setDemo(i) }, 700)
  }
  const toggleFull = () => { if (document.fullscreenElement) document.exitFullscreen(); else ref.current?.requestFullscreen?.() }
  const onNode = useCallback((_: any, n: any) => setSel(n.id), [])
  const selN = N.find(x => x[0] === sel)

  const banner = mode === 'demo' ? <span className="tag warn">SIMULATED DEMO — not a real scan</span>
    : mode === 'live' ? <span className="tag live"><i className="dot ok" /> LIVE SCAN — real processing states</span>
    : mode === 'last' ? <span className="tag ok">LAST REAL SCAN ({kind.toUpperCase()}) — recorded timings</span>
    : <span className="tag muted">IDLE — run a scan or the simulated demo</span>

  return (
    <div ref={ref} className={'wf' + (full ? ' full' : '')}>
      <div className="wf-bar">
        <div className="workflow-tabs" role="group" aria-label="Choose workflow">
          <button type="button" className={'workflow-tab' + (flowType === 'url' ? ' active' : '')} aria-pressed={flowType === 'url'} onClick={() => { setFlowType('url'); setSel(null) }}>
            <Link2 size={14} /> URL Detection
          </button>
          <button type="button" className={'workflow-tab' + (flowType === 'apk' ? ' active' : '')} aria-pressed={flowType === 'apk'} onClick={() => { setFlowType('apk'); setSel(null) }}>
            <Smartphone size={14} /> APK Lab
          </button>
        </div>
        <button className="btn sm" onClick={run} disabled={!!live && !live.done}><Play size={14} /> Run demonstration</button>
        <button className="btn sm ghost" onClick={toggleFull}>{full ? <Minimize2 size={14} /> : <Maximize2 size={14} />} {full ? 'Exit' : 'Fullscreen'}</button>
        {banner}
      </div>
      <div className="wf-canvas" id="workflow-canvas" aria-label={`${flowType === 'url' ? 'URL detection' : 'APK analysis'} workflow`}>
        <ReactFlow nodes={nodes} edges={edges} fitView fitViewOptions={{ padding: 0.1 }} onNodeClick={onNode} colorMode="dark" zoomOnScroll={false} zoomOnPinch={false} zoomOnDoubleClick={false} panOnDrag={false} panOnScroll={false} nodesDraggable={false} nodesConnectable={false}>
          <Background gap={22} color="#35423C" />
        </ReactFlow>
      </div>
      <div className="wf-detail">
        {selN ? <><b>{selN[0] === 'input' ? (flowType === 'url' ? 'URL Input' : 'APK File Input') : selN[1]}</b> — {selN[3]}</> : <>Fixed pipeline view. Select a node for details.</>}
        <div className="legend">
          {flowType === 'url' ? 'URL path: input → validation → router → URL feature extraction' : 'APK path: APK file → validation → router → static analysis'}
          {' · '}Shared stages: threat intelligence → ML → explainability → risk → verdict → report.
        </div>
      </div>
    </div>
  )
}

export default function Workflow(props: { live: any; result: any }) {
  return <ReactFlowProvider><Inner {...props} /></ReactFlowProvider>
}
