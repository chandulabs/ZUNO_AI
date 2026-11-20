import { Shield, Link2, Smartphone, Brain, Radar, Workflow as WF, FileText, PanelLeftClose, PanelLeftOpen, X } from 'lucide-react'
import { Dot } from './ui'

export const NAV: { id: string; label: string; Icon: any }[] = [
  { id: 'command', label: 'Command Center', Icon: Shield },
  { id: 'scanner', label: 'URL Scanner', Icon: Link2 },
  { id: 'apk', label: 'Android APK Lab', Icon: Smartphone },
  { id: 'explain', label: 'AI Explainability', Icon: Brain },
  { id: 'threat', label: 'Threat Intelligence', Icon: Radar },
  { id: 'workflow', label: 'Detection Workflow', Icon: WF },
  { id: 'reports', label: 'Reports & History', Icon: FileText },
]

export default function Sidebar({ active, onGo, collapsed, setCollapsed, open, setOpen, online }: any) {
  const go = (id: string) => { onGo(id); setOpen(false) }
  return (
    <>
      {open && <div className="scrim" onClick={() => setOpen(false)} />}
      <aside className={'side' + (collapsed ? ' c' : '') + (open ? ' open' : '')} aria-label="Primary">
        <div className="brand">
          <div className="logo"><Shield size={22} /></div>
          <div className="brand-t"><b>ZUNO</b><small>Threat detection platform</small></div>
          <button className="icon-btn only-mobile" onClick={() => setOpen(false)} aria-label="Close menu"><X size={18} /></button>
        </div>
        <nav>
          {NAV.map(({ id, label, Icon }) => (
            <button key={id} className={'nav' + (active === id ? ' on' : '')} onClick={() => go(id)} title={label} aria-current={active === id ? 'true' : undefined}>
              <span className="nav-glow" /><Icon size={18} className="nav-ic" /><span className="nav-l">{label}</span>
            </button>
          ))}
        </nav>
        <div className="side-foot">
          <div className="sys" title={online ? 'Backend connected' : 'Backend unreachable'}>
            <Dot state={online ? 'ok' : 'bad'} /><span className="nav-l">{online ? 'System online' : 'Backend offline'}</span>
          </div>
          <button className="icon-btn only-desktop" onClick={() => setCollapsed(!collapsed)} aria-label="Collapse sidebar">{collapsed ? <PanelLeftOpen size={18} /> : <PanelLeftClose size={18} />}</button>
        </div>
      </aside>
    </>
  )
}
