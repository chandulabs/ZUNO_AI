import { useState, useEffect } from 'react'
import { Database, RefreshCw, Upload, Search, CheckCircle, AlertTriangle, Shield, HardDrive } from 'lucide-react'
import { Block, StatusBadge, Dot } from './ui'
import { api, fmtTime } from '../api'

export default function ThreatIntel({ result, health, onRefresh }: any) {
  const [stats, setStats] = useState<any>(null)
  const [updating, setUpdating] = useState(false)
  const [updateMsg, setUpdateMsg] = useState<any>(null)
  const [searchQ, setSearchQ] = useState('')
  const [searchResults, setSearchResults] = useState<any[]>([])
  const [searching, setSearching] = useState(false)
  const [importText, setImportText] = useState('')
  const [importing, setImporting] = useState(false)
  const [importResult, setImportResult] = useState<any>(null)

  const loadStats = () => {
    api('/api/threat-intelligence/status').then(setStats).catch(() => setStats(null))
  }

  useEffect(() => {
    loadStats()
  }, [])

  const handleUpdateFeed = async () => {
    setUpdating(true)
    setUpdateMsg(null)
    try {
      const res = await api('/api/threat-intelligence/update', { method: 'POST' })
      setUpdateMsg(res)
      loadStats()
      if (onRefresh) onRefresh()
    } catch (e: any) {
      setUpdateMsg({ success: false, error: e.message })
    } finally {
      setUpdating(false)
    }
  }

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!searchQ.trim()) return
    setSearching(true)
    try {
      const res = await api(`/api/threat-intelligence/search?q=${encodeURIComponent(searchQ)}`)
      setSearchResults(res || [])
    } catch {
      setSearchResults([])
    } finally {
      setSearching(false)
    }
  }

  const handleImport = async () => {
    if (!importText.trim()) return
    setImporting(true)
    setImportResult(null)
    try {
      const isJson = importText.trim().startsWith('{') || importText.trim().startsWith('[')
      const res = await api('/api/threat-intelligence/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          content: importText,
          format: isJson ? 'json' : 'csv',
          source: 'Manual Dashboard Import'
        })
      })
      setImportResult(res)
      setImportText('')
      loadStats()
      if (onRefresh) onRefresh()
    } catch (e: any) {
      setImportResult({ success: false, message: e.message })
    } finally {
      setImporting(false)
    }
  }

  const feedUpdater = stats?.feed_updater || {}
  const totalRecords = stats?.total_records ?? 0
  const malUrls = stats?.malicious_urls ?? 0
  const malDoms = stats?.malicious_domains ?? 0
  const hashes = stats?.file_hashes ?? 0

  return (
    <Block id="threat" title="Local Threat Intelligence" sub="On-premise SQLite database · OpenPhish Community Feed · 100% offline-ready" icon={<Database size={20} />} className="ti">
      {/* Feed Status and Sync Controls */}
      <div className="two">
        <div className="pcard">
          <div className="pcard-h">
            <Dot state="ok" />
            <h3>OpenPhish Community Feed</h3>
            <span className="tag sm ok">Local Database</span>
          </div>
          <div className="kv small">
            <div><span>Feed Source</span><b>OpenPhish Public Feed</b></div>
            <div><span>Offline Capability</span><b style={{ color: '#10b981' }}>Supported (Local SQLite)</b></div>
            <div><span>Last Successful Update</span><b>{fmtTime(feedUpdater.last_successful_update || stats?.last_import)}</b></div>
            <div><span>Licensing</span><small className="muted">{feedUpdater.licensing || 'Research / non-commercial'}</small></div>
          </div>
          <div style={{ marginTop: 14 }}>
            <button className="btn sm" onClick={handleUpdateFeed} disabled={updating}>
              <RefreshCw size={14} className={updating ? 'spin' : ''} />
              {updating ? 'Updating OpenPhish Feed...' : 'Update Threat Feed Now'}
            </button>
          </div>
          {updateMsg && (
            <div className={`alert tight ${updateMsg.success ? 'ok' : 'warn'}`} style={{ marginTop: 10 }}>
              {updateMsg.success ? (
                <span><CheckCircle size={14} style={{ display: 'inline', marginRight: 4 }} /> Ingested {updateMsg.records_added} new records ({updateMsg.duplicates_skipped} duplicates skipped).</span>
              ) : (
                <span><AlertTriangle size={14} style={{ display: 'inline', marginRight: 4 }} /> Feed update note: {updateMsg.error}. Continuing with existing local database.</span>
              )}
            </div>
          )}
        </div>

        <div className="pcard">
          <div className="pcard-h">
            <HardDrive size={16} />
            <h3>Local Database Statistics</h3>
          </div>
          <div className="stat-grid" style={{ gridTemplateColumns: 'repeat(2, 1fr)', gap: 8, margin: '8px 0' }}>
            <div className="stat" style={{ padding: '8px 12px' }}>
              <div className="stat-v" style={{ fontSize: 20 }}>{totalRecords.toLocaleString()}</div>
              <div className="stat-l">Total Indicators</div>
            </div>
            <div className="stat" style={{ padding: '8px 12px' }}>
              <div className="stat-v" style={{ fontSize: 20, color: '#ef4444' }}>{malUrls.toLocaleString()}</div>
              <div className="stat-l">Malicious URLs</div>
            </div>
            <div className="stat" style={{ padding: '8px 12px' }}>
              <div className="stat-v" style={{ fontSize: 20, color: '#f59e0b' }}>{malDoms.toLocaleString()}</div>
              <div className="stat-l">Malicious Domains</div>
            </div>
            <div className="stat" style={{ padding: '8px 12px' }}>
              <div className="stat-v" style={{ fontSize: 20, color: '#22d3ee' }}>{hashes.toLocaleString()}</div>
              <div className="stat-l">File Hashes (SHA-256)</div>
            </div>
          </div>
          <p className="hint">Zero external API dependencies. All indicators are matched locally.</p>
        </div>
      </div>

      {/* Target Scan Results if a URL/APK scan is active */}
      {result && result.threat_intel && (
        <div className="panel" style={{ marginTop: 16 }}>
          <h4>Threat Feed Match For Target: <code>{result.url || result.package || result.target}</code></h4>
          {result.threat_summary && (
            <div className={`summary ${result.threat_summary.status === 'MALICIOUS' ? 'hit' : ''}`} style={{ marginTop: 8 }}>
              <div className="summary-h">
                <span>Result:</span>
                <StatusBadge s={result.threat_summary.status} />
              </div>
              <p>{result.threat_summary.message}</p>
              {result.threat_summary.match_type && (
                <div className="kv small">
                  <div><span>Match Type</span><b>{result.threat_summary.match_type.replace('_', ' ').toUpperCase()}</b></div>
                  <div><span>Feed Source</span><b>{result.threat_summary.feed_source || 'Local Database'}</b></div>
                  {result.threat_summary.category && <div><span>Category</span><b>{result.threat_summary.category}</b></div>}
                  {result.threat_summary.malware_family && <div><span>Malware Family</span><b>{result.threat_summary.malware_family}</b></div>}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Database Search & Manual Import Tabs */}
      <div className="two" style={{ marginTop: 16 }}>
        <div className="panel">
          <h4>Search Local Threat Database</h4>
          <form onSubmit={handleSearch} style={{ display: 'flex', gap: 8, marginTop: 8 }}>
            <input
              type="text"
              value={searchQ}
              onChange={e => setSearchQ(e.target.value)}
              placeholder="Search URL, domain or hash..."
              style={{ flex: 1 }}
            />
            <button className="btn sm" disabled={searching}>
              <Search size={14} /> Search
            </button>
          </form>
          {searchResults.length > 0 && (
            <div style={{ marginTop: 12, maxHeight: 180, overflowY: 'auto' }}>
              <table className="cmp">
                <thead><tr><th>Type</th><th>Indicator</th><th>Level</th><th>Source</th></tr></thead>
                <tbody>
                  {searchResults.map((r, i) => (
                    <tr key={i}>
                      <td><span className="tag sm">{r.indicator_type}</span></td>
                      <td style={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={r.indicator_value}>{r.indicator_value}</td>
                      <td><StatusBadge s={r.threat_level} /></td>
                      <td>{r.source}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {searchQ && !searching && searchResults.length === 0 && (
            <div className="muted sm" style={{ marginTop: 8 }}>No matching records found in local database.</div>
          )}
        </div>

        <div className="panel">
          <h4>Manual Feed Ingestion (CSV / JSON)</h4>
          <p className="hint">Paste raw threat lists (one URL per line or CSV with url,threat_level,source):</p>
          <textarea
            value={importText}
            onChange={e => setImportText(e.target.value)}
            rows={3}
            placeholder="http://malicious-phish-domain.com/login&#10;https://another-phish-link.xyz/verify"
            style={{ width: '100%', background: '#080d1a', border: '1px solid #1f2745', borderRadius: 6, color: '#e2e8f0', padding: 8, fontSize: 12, fontFamily: 'monospace' }}
          />
          <div style={{ marginTop: 8 }}>
            <button className="btn sm" onClick={handleImport} disabled={importing || !importText.trim()}>
              <Upload size={14} /> {importing ? 'Ingesting...' : 'Import to Local DB'}
            </button>
          </div>
          {importResult && (
            <div className={`alert tight ${importResult.success ? 'ok' : 'bad'}`} style={{ marginTop: 8 }}>
              {importResult.message}
            </div>
          )}
        </div>
      </div>
    </Block>
  )
}
