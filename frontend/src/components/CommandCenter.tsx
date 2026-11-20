import { Activity, ShieldAlert, ShieldCheck, Smartphone, Server, Cpu, Database, RefreshCw, Zap } from 'lucide-react'
import { Block, CountUp, Dot, VerdictTag } from './ui'
import { fmtTime } from '../api'

export default function CommandCenter({ health, stats, onOpen }: any) {
  const online = !!health
  const cards = [
    { l: 'Total scans', v: stats?.total, I: Activity, c: '#8b5cf6', s: stats ? `${stats.url_scans || 0} URL · ${stats.apk_analyses || 0} APK` : '' },
    { l: 'Phishing detected', v: stats?.phishing, I: ShieldAlert, c: '#ef4444', s: stats ? `${stats.suspicious || 0} suspicious URLs` : '' },
    { l: 'Safe URLs verified', v: stats?.safe, I: ShieldCheck, c: '#10b981', s: stats ? `${stats.unknown || 0} unverified/unknown` : '' },
    { l: 'Android APK analyses', v: stats?.apk_analyses, I: Smartphone, c: '#22d3ee', s: stats ? `${stats.last_24h || 0} in last 24 h` : '' },
  ]

  const activeModelName = health?.active_model ? health.active_model.replace('_', ' ').toUpperCase() : 'RANDOM FOREST'
  const modelLoaded = health?.model_loaded
  const tiRecords = health?.threat_intelligence?.total_records ?? 0
  const lastFeedUpdate = health?.threat_intelligence?.last_feed_update

  return (
    <Block id="command" title="Command Center" sub="On-premise hybrid AI detection · 100% API-key-free" icon={<Activity size={20} />} className="cmd">
      <div className="stat-grid">
        {cards.map(({ l, v, I, c, s }) => (
          <div className="stat" key={l} style={{ ['--c' as any]: c }}>
            <div className="stat-i"><I size={18} /></div>
            <div className="stat-v"><CountUp value={online ? v : null} /></div>
            <div className="stat-l">{l}</div>
            <div className="stat-s">{s || ' '}</div>
          </div>
        ))}
      </div>

      <div className="cmd-lower">
        <div className="panel">
          <h4>Infrastructure &amp; Model Status</h4>
          <ul className="status-list">
            <li>
              <Server size={15} />
              <span>Backend API</span>
              <b><Dot state={online ? 'ok' : 'bad'} />{online ? 'Connected (Local Server)' : 'Unreachable'}</b>
            </li>
            <li>
              <Cpu size={15} />
              <span>Active Model</span>
              <b>
                <Dot state={!online ? 'off' : modelLoaded ? 'ok' : 'warn'} />
                {!online ? 'Unknown' : modelLoaded ? `${activeModelName} (LOADED)` : 'MODEL NOT TRAINED'}
              </b>
            </li>
            <li>
              <Database size={15} />
              <span>Threat Intel DB</span>
              <b>
                <Dot state={tiRecords > 0 ? 'ok' : 'warn'} />
                {tiRecords > 0 ? `${tiRecords.toLocaleString()} local indicators` : 'Local DB Empty'}
              </b>
            </li>
            <li>
              <RefreshCw size={15} />
              <span>OpenPhish Feed</span>
              <b>
                <Dot state={lastFeedUpdate ? 'ok' : 'warn'} />
                {lastFeedUpdate ? fmtTime(lastFeedUpdate) : 'Ready (Offline cache)'}
              </b>
            </li>
            <li>
              <Zap size={15} />
              <span>External API Keys</span>
              <b><Dot state="ok" />Zero (100% On-Premise)</b>
            </li>
          </ul>
        </div>

        <div className="panel">
          <h4>Recent Activity</h4>
          {!stats?.recent?.length ? (
            <div className="muted">No scans yet — analyze a URL or APK to get started.</div>
          ) : (
            <ul className="recent">
              {stats.recent.map((x: any) => (
                <li key={x.id}>
                  <button onClick={() => onOpen(x.id)}>
                    <span className="k">{x.kind.toUpperCase()}</span>
                    <span className="t" title={x.target}>{x.target}</span>
                    <VerdictTag v={x.verdict} />
                    <time>{fmtTime(x.created)}</time>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </Block>
  )
}
