import { useState } from 'react'
import { Link2, Search, Loader2, ChevronDown, ArrowDown, Cpu, Database, AlertCircle } from 'lucide-react'
import { Block, VerdictTag, Meter, StatusBadge } from './ui'
import { api, VERDICT_COLOR, pct, STAGES } from '../api'

const LABEL: any = {
  input: 'Receiving input',
  validation: 'Validating URL structure',
  normalization: 'Normalizing URL & canonicalization',
  features: 'Extracting 22 lexical features',
  rules: 'Evaluating heuristic rules',
  threat_intel: 'Querying local threat intelligence',
  random_forest: 'Random Forest inference',
  xgboost: 'XGBoost inference',
  active_model: 'Active model scoring',
  shap: 'Computing SHAP TreeExplainer',
  risk: 'Calibrating multi-layer risk',
  verdict: 'Assigning verdict',
  report: 'Saving forensic record'
}

export function validateUrl(v: string): string {
  const s = v.trim()
  if (!s) return 'Please enter a URL.'
  if (s.length > 2048) return 'URL is too long (max 2048 characters).'
  if (/\s/.test(s)) return 'URL must not contain spaces.'
  if (/^(javascript|data|mailto|file|ftp):/i.test(s)) return 'Only http and https URLs are supported.'
  if (!/^https?:\/\//i.test(s) && !/^[^/]+\.[^/]+/.test(s)) return 'Enter a valid URL such as https://example.com/login'
  return ''
}

export default function UrlScanner({ scan, begin, end, live, result, onResult, goto }: any) {
  const [u, setU] = useState(''), [err, setErr] = useState(''), [busy, setBusy] = useState(false), [showF, setShowF] = useState(false)
  const r = result?.kind === 'url' ? result : null

  const go = async () => {
    const e = validateUrl(u)
    setErr(e)
    if (e) return
    setBusy(true)
    const pid = begin('url')
    try {
      const j = await api('/api/scan/url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: u, scan_id: pid })
      })
      onResult(j)
    } catch (x: any) {
      setErr(x.message)
    } finally {
      setBusy(false)
      end()
    }
  }

  const stages = live?.mode === 'url' ? live.stages : null
  const doneN = stages ? STAGES.filter(s => stages[s] === 'done' || stages[s] === 'skipped').length : 0
  const cur = stages ? STAGES.find(s => stages[s] === 'active') : null

  return (
    <Block id="scanner" title="URL Scanner" sub="Rules · Random Forest &amp; XGBoost · OpenPhish Feed · SHAP" icon={<Link2 size={20} />} className="scanner">
      <form className="scan-form" onSubmit={e => { e.preventDefault(); go() }}>
        <input
          value={u}
          onChange={x => { setU(x.target.value); setErr('') }}
          placeholder="https://example.com/login"
          aria-label="URL to analyse"
          spellCheck={false}
          autoComplete="off"
        />
        <button className="btn" disabled={busy}>
          {busy ? <Loader2 size={16} className="spin" /> : <Search size={16} />} Analyze URL
        </button>
      </form>
      {err && <div className="alert bad" role="alert">{err}</div>}
      <p className="hint">Zero network connections are made to the target. All analysis runs 100% locally on this server.</p>

      {busy && (
        <div className="scanning">
          <div className="scanline" />
          <div className="prog"><div style={{ width: `${Math.max(8, (doneN / STAGES.length) * 100)}%` }} /></div>
          <span>{cur ? LABEL[cur] || cur : 'Analyzing'}… ({doneN}/{STAGES.length})</span>
        </div>
      )}

      {!r && !busy && (
        <div className="empty">Enter a URL to see the verdict, risk score, rule indicators, local threat intelligence match, and SHAP explanation.</div>
      )}

      {r && !busy && <Result r={r} showF={showF} setShowF={setShowF} goto={goto} />}
    </Block>
  )
}

function Result({ r, showF, setShowF, goto }: any) {
  const v = r.verdict, c = VERDICT_COLOR[v], risk = r.risk || {}, sh = r.shap
  const ml = r.ml || {}
  const activeModelName = ml.active_model_name ? ml.active_model_name.replace('_', ' ').toUpperCase() : 'RANDOM FOREST'

  return (
    <div className="result fade-in" style={{ ['--c' as any]: c }}>
      <div className="verdict-row">
        <div>
          <div className="muted sm">Final Verdict</div>
          <VerdictTag v={v} big />
          {risk.category && <span className="tag sm warn" style={{ marginLeft: 8 }}>{risk.category}</span>}
        </div>
        <div className="grow">
          <div className="muted sm">Risk Score · Confidence: {risk.confidence?.toUpperCase()}</div>
          <Meter score={risk.score ?? 0} color={c} />
        </div>
      </div>

      <div className="tgt" title={r.url}>{r.url}</div>
      {v === 'UNKNOWN' && (
        <div className="alert warn">
          <AlertCircle size={15} style={{ display: 'inline', marginRight: 4 }} />
          Not enough positive evidence to classify this URL. It is <b>not</b> treated as safe.
        </div>
      )}
      {(risk.notes || []).filter((n: string) => v !== 'UNKNOWN').map((n: string) => (
        <p className="hint" key={n}>{n}</p>
      ))}

      <div className="two">
        {/* Machine Learning Panel */}
        <div className="panel">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h4>Machine Learning Detection</h4>
            <span className="tag sm ok"><Cpu size={12} style={{ marginRight: 3 }} /> {activeModelName}</span>
          </div>
          {ml.available ? (
            <>
              <div className="big-n">
                {pct(ml.probability)}
                <small> malicious probability</small>
              </div>
              {ml.comparison && (
                <div className="kv small" style={{ marginTop: 8 }}>
                  <div>
                    <span>Random Forest</span>
                    <b>{ml.comparison.random_forest?.probability != null ? pct(ml.comparison.random_forest.probability) : 'N/A'}</b>
                  </div>
                  <div>
                    <span>XGBoost</span>
                    <b>{ml.comparison.xgboost?.probability != null ? pct(ml.comparison.xgboost.probability) : 'N/A'}</b>
                  </div>
                </div>
              )}
            </>
          ) : (
            <div className="alert warn tight">
              <b>MODEL NOT TRAINED</b><br />
              {ml.detail || 'No trained model found.'}
            </div>
          )}

          <h4 style={{ marginTop: 14 }}>Detection Indicators <small className="muted">(Rule-based)</small></h4>
          {r.rules?.triggered?.length ? (
            <ul className="ind">
              {r.rules.triggered.map((t: any) => (
                <li key={t.id}><span>{t.label}</span><b>+{t.weight}</b></li>
              ))}
            </ul>
          ) : (
            <div className="muted sm">No rule-based indicators triggered.</div>
          )}
        </div>

        {/* Local Threat Intelligence Panel */}
        <div className="panel">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h4>Local Threat Intelligence</h4>
            <span className="tag sm"><Database size={12} style={{ marginRight: 3 }} /> OpenPhish Feed</span>
          </div>
          {(r.threat_intel || []).map((t: any, idx: number) => (
            <div className="ti-row" key={idx}>
              <span>{t.source || 'Local Threat DB'}</span>
              <StatusBadge s={t.status} />
            </div>
          ))}
          {r.threat_summary && <p className="hint" style={{ marginTop: 8 }}>{r.threat_summary.message}</p>}
          <button className="link" onClick={() => goto('threat')} style={{ marginTop: 8 }}>
            Full Threat Intel Report <ArrowDown size={13} />
          </button>
        </div>
      </div>

      {/* SHAP Preview */}
      <div className="panel">
        <h4>SHAP Explainability Preview <small className="muted">(Random Forest TreeExplainer)</small></h4>
        {sh?.available ? (
          <>
            <div className="mini-bars">
              {[...(sh.top_positive || []).slice(0, 3), ...(sh.top_negative || []).slice(0, 2)].map((c: any) => {
                const mx = Math.max(...(sh.contributions || []).map((x: any) => Math.abs(x.shap)), 1e-9)
                return (
                  <div className="mb" key={c.feature}>
                    <span>{c.label}</span>
                    <div className="mb-t">
                      <div className={c.shap > 0 ? 'pos' : 'neg'} style={{ width: `${(Math.abs(c.shap) / mx) * 100}%` }} />
                    </div>
                    <b className={c.shap > 0 ? 'p' : 'n'}>{c.shap > 0 ? '+' : ''}{c.shap.toFixed(3)}</b>
                  </div>
                )
              })}
            </div>
            <p className="hint">{sh.summary}</p>
          </>
        ) : (
          <div className="alert warn tight">
            <b>SHAP unavailable.</b> {sh?.reason || 'Requires a trained Random Forest model.'}
          </div>
        )}
        <button className="link" onClick={() => goto('explain')}>
          Open Model Comparison &amp; AI Explainability <ArrowDown size={13} />
        </button>
      </div>

      {/* Extracted Features Toggle */}
      <button className="toggle" onClick={() => setShowF(!showF)}>
        Extracted URL Features ({r.feature_table?.length || 0}) <ChevronDown size={14} className={showF ? 'rot' : ''} />
      </button>
      {showF && (
        <div className="feat-grid">
          {(r.feature_table || []).map((f: any) => (
            <div key={f.name} title={f.description}>
              <span>{f.label}</span>
              <b>{String(f.value)}</b>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
