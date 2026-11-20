import { useEffect, useState } from 'react'
import { Brain, Info, CheckCircle2, Cpu, BarChart2, Check, RefreshCw } from 'lucide-react'
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell, ReferenceLine, CartesianGrid } from 'recharts'
import { api, pct, fmtTime } from '../api'

const tip = { background: '#202927', border: '1px solid #46564d', borderRadius: 8, color: '#f3f1e7', fontSize: 12 }

export default function Explain({ result, refreshKey, onModelChanged }: any) {
  const [globalData, setGlobalData] = useState<any>(null)
  const [compareData, setCompareData] = useState<any>(null)
  const [switching, setSwitching] = useState(false)
  const [training, setTraining] = useState(false)
  const [trainMsg, setTrainMsg] = useState<string | null>(null)

  const loadData = () => {
    api('/api/explain/global').then(setGlobalData).catch(() => setGlobalData(null))
    api('/api/models/compare').then(setCompareData).catch(() => setCompareData(null))
  }

  useEffect(() => {
    loadData()
  }, [refreshKey])

  const handleSelectModel = async (modelName: string) => {
    setSwitching(true)
    try {
      await api('/api/models/select', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ model: modelName })
      })
      loadData()
      if (onModelChanged) onModelChanged(modelName)
    } catch {
      // ignore
    } finally {
      setSwitching(false)
    }
  }

  const handleRetrain = async () => {
    setTraining(true)
    setTrainMsg(null)
    try {
      const res = await api('/api/models/train', { method: 'POST' })
      setTrainMsg('Models trained and evaluated successfully!')
      loadData()
      if (onModelChanged) onModelChanged()
    } catch (e: any) {
      setTrainMsg(`Training error: ${e.message}`)
    } finally {
      setTraining(false)
    }
  }

  const r = result?.kind === 'url' ? result : null
  const sh = r?.shap
  const modelStatus = globalData?.model
  const activeModel = modelStatus?.active_model || 'random_forest'
  const imp = globalData?.importance

  const rfMetrics = compareData?.models?.random_forest || compareData?.random_forest
  const xgbMetrics = compareData?.models?.xgboost || compareData?.xgboost

  const data = sh?.available ? sh.contributions.map((c: any) => ({ ...c, name: c.label })) : []

  return (
    <div id="explain" className="sub">
      <header className="block-h">
        <div className="block-ic"><Brain size={20} /></div>
        <div className="block-t">
          <h2>Machine Learning &amp; AI Explainability</h2>
          <p>Random Forest vs XGBoost side-by-side comparison · SHAP TreeExplainer · 100% on-premise</p>
        </div>
      </header>

      {/* Model Comparison Dashboard */}
      <div className="panel" style={{ marginBottom: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12, flexWrap: 'wrap', gap: 8 }}>
          <div>
            <h4 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: 6 }}>
              <Cpu size={16} color="#8b5cf6" /> Model Comparison Dashboard
            </h4>
            <span className="muted sm">Both models evaluated on domain-isolated held-out test splits without data leakage.</span>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn sm" onClick={handleRetrain} disabled={training}>
              <RefreshCw size={13} className={training ? 'spin' : ''} />
              {training ? 'Training Models...' : 'Retrain & Compare Models'}
            </button>
          </div>
        </div>

        {trainMsg && <div className="alert tight ok" style={{ marginBottom: 12 }}>{trainMsg}</div>}

        <div className="two" style={{ gap: 12 }}>
          {/* Random Forest Card */}
          <div className={`pcard ${activeModel === 'random_forest' ? 'hit' : ''}`} style={{ borderColor: activeModel === 'random_forest' ? '#8b5cf6' : undefined }}>
            <div className="pcard-h">
              <h3>Random Forest Classifier</h3>
              {activeModel === 'random_forest' ? (
                <span className="tag sm ok"><Check size={11} style={{ marginRight: 3 }} /> ACTIVE MODEL</span>
              ) : (
                <button className="btn sm" onClick={() => handleSelectModel('random_forest')} disabled={switching}>
                  Set as Active
                </button>
              )}
            </div>
            {rfMetrics ? (
              <div className="kv small" style={{ marginTop: 8 }}>
                <div><span>Test Accuracy</span><b>{pct(rfMetrics.accuracy)}</b></div>
                <div><span>Precision</span><b>{pct(rfMetrics.precision)}</b></div>
                <div><span>Recall</span><b>{pct(rfMetrics.recall)}</b></div>
                <div><span>F1-Score</span><b style={{ color: '#8b5cf6' }}>{rfMetrics.f1_score?.toFixed(4)}</b></div>
                <div><span>ROC-AUC</span><b>{rfMetrics.roc_auc?.toFixed(4)}</b></div>
                <div><span>Inference Latency</span><b>{rfMetrics.latency_ms?.toFixed(2)} ms/URL</b></div>
                <div><span>SHAP Explainability</span><b style={{ color: '#10b981' }}>Supported (TreeExplainer)</b></div>
              </div>
            ) : (
              <div className="alert warn tight" style={{ marginTop: 8 }}>MODEL NOT TRAINED</div>
            )}
            {rfMetrics?.confusion_matrix && (
              <div style={{ marginTop: 8, fontSize: 11 }} className="muted">
                Confusion Matrix: TP={rfMetrics.confusion_matrix.true_positives}, TN={rfMetrics.confusion_matrix.true_negatives}, FP={rfMetrics.confusion_matrix.false_positives}, FN={rfMetrics.confusion_matrix.false_negatives}
              </div>
            )}
          </div>

          {/* XGBoost Card */}
          <div className={`pcard ${activeModel === 'xgboost' ? 'hit' : ''}`} style={{ borderColor: activeModel === 'xgboost' ? '#8b5cf6' : undefined }}>
            <div className="pcard-h">
              <h3>XGBoost Classifier</h3>
              {activeModel === 'xgboost' ? (
                <span className="tag sm ok"><Check size={11} style={{ marginRight: 3 }} /> ACTIVE MODEL</span>
              ) : (
                <button className="btn sm" onClick={() => handleSelectModel('xgboost')} disabled={switching}>
                  Set as Active
                </button>
              )}
            </div>
            {xgbMetrics ? (
              <div className="kv small" style={{ marginTop: 8 }}>
                <div><span>Test Accuracy</span><b>{pct(xgbMetrics.accuracy)}</b></div>
                <div><span>Precision</span><b>{pct(xgbMetrics.precision)}</b></div>
                <div><span>Recall</span><b>{pct(xgbMetrics.recall)}</b></div>
                <div><span>F1-Score</span><b style={{ color: '#8b5cf6' }}>{xgbMetrics.f1_score?.toFixed(4)}</b></div>
                <div><span>ROC-AUC</span><b>{xgbMetrics.roc_auc?.toFixed(4)}</b></div>
                <div><span>Inference Latency</span><b>{xgbMetrics.latency_ms?.toFixed(2)} ms/URL</b></div>
                <div><span>Boosting Type</span><b>Gradient Boosted Trees</b></div>
              </div>
            ) : (
              <div className="alert warn tight" style={{ marginTop: 8 }}>MODEL NOT TRAINED</div>
            )}
            {xgbMetrics?.confusion_matrix && (
              <div style={{ marginTop: 8, fontSize: 11 }} className="muted">
                Confusion Matrix: TP={xgbMetrics.confusion_matrix.true_positives}, TN={xgbMetrics.confusion_matrix.true_negatives}, FP={xgbMetrics.confusion_matrix.false_positives}, FN={xgbMetrics.confusion_matrix.false_negatives}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Prediction Summary for Target URL */}
      <div className="two">
        <div className="panel">
          <h4>Prediction Summary For Scanned URL</h4>
          {!r ? (
            <div className="muted">Analyse a URL (or open one from history) to see its explanation.</div>
          ) : (
            <>
              <div className="tgt" title={r.url}>{r.url}</div>
              {r.ml?.available ? (
                <>
                  <div className="big-n">
                    {pct(r.ml.probability)}
                    <small> malicious probability ({r.ml.active_model_name?.replace('_', ' ').toUpperCase()})</small>
                  </div>
                  {r.ml.comparison && (
                    <div className="kv small" style={{ marginTop: 8 }}>
                      <div>
                        <span>Random Forest</span>
                        <b>{r.ml.comparison.random_forest?.probability != null ? pct(r.ml.comparison.random_forest.probability) : 'N/A'}</b>
                      </div>
                      <div>
                        <span>XGBoost</span>
                        <b>{r.ml.comparison.xgboost?.probability != null ? pct(r.ml.comparison.xgboost.probability) : 'N/A'}</b>
                      </div>
                    </div>
                  )}
                </>
              ) : (
                <div className="alert warn tight"><b>MODEL NOT TRAINED</b><br />No probability was computed for this URL.</div>
              )}
              {sh?.available && (
                <div className="kv small" style={{ marginTop: 8 }}>
                  <div><span>Baseline (avg. training URL)</span><b>{pct(sh.base_value)}</b></div>
                  <div><span>Model Decision</span><b>{sh.probability >= 0.5 ? 'Phishing' : 'Legitimate'}</b></div>
                </div>
              )}
              {sh?.available && <p className="hint">{sh.summary}</p>}
            </>
          )}
        </div>

        <div className="panel">
          <h4>Active Model Architecture</h4>
          {modelStatus?.available ? (
            <div className="kv small">
              <div><span>Active Classifier</span><b style={{ color: '#8b5cf6' }}>{activeModel.replace('_', ' ').toUpperCase()}</b></div>
              <div><span>Feature Count</span><b>{modelStatus.feature_count} lexical &amp; host features</b></div>
              <div><span>Inference Mode</span><b style={{ color: '#10b981' }}>100% Local / On-Premise</b></div>
              <div><span>External API Keys</span><b>None (Zero API Dependencies)</b></div>
              <div><span>SHAP Explainer</span><b>{modelStatus.models?.random_forest?.shap_available ? 'Ready (TreeExplainer)' : 'Unavailable'}</b></div>
            </div>
          ) : (
            <div className="alert warn tight">
              <b>MODELS NOT TRAINED</b><br />
              Run <code>python -m training.train</code> to generate model artifacts.
            </div>
          )}
        </div>
      </div>

      {/* SHAP Explanation for Random Forest */}
      {r && !sh?.available && (
        <div className="panel" style={{ marginTop: 16 }}>
          <div className="alert warn tight">
            <Info size={14} /> <b>SHAP explanation unavailable.</b> {sh?.reason || 'Requires a trained Random Forest model.'}
          </div>
          <h4 style={{ marginTop: 12 }}>Rule-based Heuristic Indicators <small className="muted">(Deterministic Heuristics)</small></h4>
          {r.rules?.triggered?.length ? (
            <ul className="ind">
              {r.rules.triggered.map((t: any) => (
                <li key={t.id}><span>{t.label}</span><b>+{t.weight}</b></li>
              ))}
            </ul>
          ) : (
            <div className="muted">No heuristic rule triggered.</div>
          )}
        </div>
      )}

      {sh?.available && (
        <>
          <div className="panel" style={{ marginTop: 16 }}>
            <h4>Feature Contribution Chart <small className="muted">(SHAP TreeExplainer · Red = toward Phishing, Green = toward Legitimate)</small></h4>
            <div className="chart" style={{ height: Math.max(260, data.length * 28 + 40) }}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={data} layout="vertical" margin={{ left: 8, right: 24, top: 4, bottom: 4 }}>
                  <CartesianGrid stroke="#35423c" horizontal={false} />
                  <XAxis type="number" stroke="#829087" tick={{ fontSize: 11 }} tickFormatter={(v: number) => v.toFixed(2)} />
                  <YAxis type="category" dataKey="name" width={150} stroke="#a2ada6" tick={{ fontSize: 11 }} />
                  <Tooltip contentStyle={tip} cursor={{ fill: '#ffffff0d' }} formatter={(v: any, _n: any, p: any) => [`${(+v).toFixed(4)} (value: ${p.payload.value})`, 'SHAP']} />
                  <ReferenceLine x={0} stroke="#829087" />
                  <Bar dataKey="shap" radius={3} animationDuration={800}>
                    {data.map((d: any) => (
                      <Cell key={d.feature} fill={d.shap > 0 ? '#e27c75' : d.shap < 0 ? '#8ddb78' : '#829087'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="two" style={{ marginTop: 16 }}>
            <div className="panel">
              <h4>Top Positive Features <small className="muted">(pushed toward Phishing)</small></h4>
              {sh.top_positive?.length ? (
                <ul className="ind">
                  {sh.top_positive.map((c: any) => (
                    <li key={c.feature}>
                      <span><b>{c.label}</b><br /><small className="muted">{c.description}</small></span>
                      <b className="p">+{c.shap.toFixed(3)}</b>
                    </li>
                  ))}
                </ul>
              ) : <div className="muted sm">None.</div>}
            </div>

            <div className="panel">
              <h4>Top Negative Features <small className="muted">(pushed toward Legitimate)</small></h4>
              {sh.top_negative?.length ? (
                <ul className="ind">
                  {sh.top_negative.map((c: any) => (
                    <li key={c.feature}>
                      <span><b>{c.label}</b><br /><small className="muted">{c.description}</small></span>
                      <b className="n">{c.shap.toFixed(3)}</b>
                    </li>
                  ))}
                </ul>
              ) : <div className="muted sm">None.</div>}
            </div>
          </div>

          <div className="panel" style={{ marginTop: 16 }}>
            <h4>Individual URL Characteristics &amp; SHAP Values</h4>
            <table className="tbl">
              <thead><tr><th>Feature</th><th>Extracted Value</th><th>SHAP Impact</th><th>Explanation</th></tr></thead>
              <tbody>
                {sh.contributions.map((c: any) => (
                  <tr key={c.feature}>
                    <td>{c.label}</td>
                    <td>{String(c.value)}</td>
                    <td className={c.shap > 0 ? 'p' : c.shap < 0 ? 'n' : ''}>{c.shap > 0 ? '+' : ''}{c.shap.toFixed(4)}</td>
                    <td className="muted">{c.description}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {/* Global Feature Importance */}
      <div className="panel" style={{ marginTop: 16 }}>
        <h4>Global Feature Importance <small className="muted">(Random Forest Gini Impurity)</small></h4>
        {imp?.available && imp.features?.length ? (
          <div className="chart" style={{ height: imp.features.length * 24 + 40 }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={imp.features} layout="vertical" margin={{ left: 8, right: 24 }}>
                <CartesianGrid stroke="#35423c" horizontal={false} />
                <XAxis type="number" stroke="#829087" tick={{ fontSize: 11 }} />
                <YAxis type="category" dataKey="label" width={150} stroke="#a2ada6" tick={{ fontSize: 11 }} />
                <Tooltip contentStyle={tip} cursor={{ fill: '#ffffff0d' }} formatter={(v: any) => (+v).toFixed(4)} />
                <Bar dataKey="importance" fill="#a3e635" radius={3} animationDuration={800} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        ) : (
          <div className="muted">Global feature importance requires a trained model. Train one with <code>python -m training.train</code>.</div>
        )}
      </div>
    </div>
  )
}
