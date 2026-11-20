import { useEffect, useRef, useState, ReactNode } from 'react'
import { VERDICT_COLOR, TI_STATUS } from '../api'

export function VerdictTag({ v, big }: { v: string; big?: boolean }) {
  const c = VERDICT_COLOR[v] || '#94a3b8'
  return <span className={'tag' + (big ? ' big' : '')} style={{ background: c + '26', color: c, borderColor: c + '66' }}>{v}</span>
}

export function StatusBadge({ s }: { s: string }) {
  const m = TI_STATUS[s] || TI_STATUS.UNKNOWN
  return <span className={'tag' + (s === 'MALICIOUS' ? ' pulse-red' : '')} style={{ background: m.color + '24', color: m.color, borderColor: m.color + '66' }}>{m.label}</span>
}

export function Dot({ state }: { state: 'ok' | 'warn' | 'bad' | 'off' }) {
  return <span className={'dot ' + state} />
}

/** Count-up animation for statistics (respects reduced motion). */
export function CountUp({ value }: { value: number | null | undefined }) {
  const [n, setN] = useState(0), from = useRef(0)
  useEffect(() => {
    if (value == null) return
    const reduce = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches
    if (reduce) { setN(value); return }
    const a = from.current, t0 = performance.now(); let raf = 0
    const step = (t: number) => {
      const k = Math.min(1, (t - t0) / 800), e = 1 - Math.pow(1 - k, 3)
      setN(Math.round(a + (value - a) * e)); if (k < 1) raf = requestAnimationFrame(step); else from.current = value
    }
    raf = requestAnimationFrame(step); return () => cancelAnimationFrame(raf)
  }, [value])
  return <>{value == null ? '—' : n.toLocaleString()}</>
}

export function Block({ id, title, sub, icon, className = '', children, right }: { id: string; title: string; sub?: string; icon: ReactNode; className?: string; children: ReactNode; right?: ReactNode }) {
  return (
    <section id={id} className={'block ' + className}>
      <header className="block-h">
        <div className="block-ic">{icon}</div>
        <div className="block-t"><h2>{title}</h2>{sub && <p>{sub}</p>}</div>
        {right && <div className="block-r">{right}</div>}
      </header>
      {children}
    </section>
  )
}

export function Meter({ score, color }: { score: number; color: string }) {
  const [w, setW] = useState(0)
  useEffect(() => { const t = setTimeout(() => setW(score), 60); return () => clearTimeout(t) }, [score])
  return <div className="meter" role="meter" aria-valuenow={score} aria-valuemin={0} aria-valuemax={100}><div className="meter-fill" style={{ width: w + '%', background: `linear-gradient(90deg,#22d3ee,${color})` }} /><span>{score}/100</span></div>
}

export const Empty = ({ children }: { children: ReactNode }) => <div className="empty">{children}</div>
