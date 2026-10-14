

import { useCallback, useEffect, useState } from 'react'
import {
  Activity,
  AlertTriangle,
  ArrowDownRight,
  ArrowUpRight,
  CheckCircle2,
  CircleDot,
  Clock3,
  RefreshCw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Wifi,
} from 'lucide-react'
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import './App.css'

type SecurityEvent = {
  id: number
  event_type?: string
  event_name?: string
  severity?: string
  source_ip?: string
  message?: string
  created_at?: string
  timestamp?: string
  metadata?: Record<string, unknown>
}

type SecurityAlert = {
  id: number
  rule_id?: string
  title?: string
  name?: string
  description?: string
  severity?: string
  status?: string
  source_ip?: string
  created_at?: string
  acknowledged_at?: string | null
}

type Summary = {
  total_events?: number
  events_count?: number
  total_alerts?: number
  open_alerts?: number
  critical_alerts?: number
  critical_incidents?: number
}

async function api<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
  })

  if (!response.ok) {
    const message = await response.text()
    throw new Error(message || `Request failed (${response.status})`)
  }

  return response.json() as Promise<T>
}

function severityClass(value?: string) {
  const severity = (value || 'low').toLowerCase()
  if (severity === 'critical') return 'critical'
  if (severity === 'high') return 'high'
  if (severity === 'medium' || severity === 'moderate') return 'medium'
  return 'low'
}

function formatTime(value?: string) {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleString([], {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

function eventName(event: SecurityEvent) {
  return event.event_type || event.event_name || 'Security event'
}

function alertName(alert: SecurityAlert) {
  return alert.title || alert.name || alert.rule_id || 'Security alert'
}

function App() {
  const [events, setEvents] = useState<SecurityEvent[]>([])
  const [alerts, setAlerts] = useState<SecurityAlert[]>([])
  const [summary, setSummary] = useState<Summary>({})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [filter, setFilter] = useState('all')
  const [busyAlert, setBusyAlert] = useState<number | null>(null)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)

  const loadDashboard = useCallback(async () => {
    setError('')

    try {
      const [summaryData, eventData, alertData] = await Promise.all([
        api<Summary>('/api/v1/summary'),
        api<SecurityEvent[]>('/api/v1/events?limit=50'),
        api<SecurityAlert[]>('/api/v1/alerts?limit=50'),
      ])

      setSummary(summaryData)
      setEvents(Array.isArray(eventData) ? eventData : [])
      setAlerts(Array.isArray(alertData) ? alertData : [])
      setLastUpdated(new Date())
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : 'Unable to connect to the SENTINEL API.',
      )
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void loadDashboard()
    const timer = window.setInterval(() => void loadDashboard(), 15000)
    return () => window.clearInterval(timer)
  }, [loadDashboard])

  const acknowledgeAlert = async (id: number) => {
    setBusyAlert(id)
    setError('')

    try {
      await api(`/api/v1/alerts/${id}/acknowledge`, {
        method: 'PATCH',
      })
      await loadDashboard()
    } catch (err) {
      setError(
        err instanceof Error ? err.message : 'Could not acknowledge alert.',
      )
    } finally {
      setBusyAlert(null)
    }
  }

  const openAlerts = alerts.filter(
    (alert) => (alert.status || 'open').toLowerCase() === 'open',
  )

  const criticalAlerts = alerts.filter(
    (alert) => severityClass(alert.severity) === 'critical',
  )

  const visibleEvents = events.filter((event) => {
    if (filter === 'all') return true
    return severityClass(event.severity) === filter
  })

  const chartData = (() => {
    const buckets = new Map<string, number>()

    for (const event of events) {
      const rawDate = event.created_at || event.timestamp
      if (!rawDate) continue

      const date = new Date(rawDate)
      if (Number.isNaN(date.getTime())) continue

      const label = date.toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
      })
      buckets.set(label, (buckets.get(label) || 0) + 1)
    }

    return [...buckets.entries()]
      .slice(-12)
      .map(([time, count]) => ({ time, count }))
  })()

  const totalEvents =
    summary.total_events ?? summary.events_count ?? events.length

  const openAlertCount = summary.open_alerts ?? openAlerts.length

  const criticalCount =
    summary.critical_alerts ??
    summary.critical_incidents ??
    criticalAlerts.length

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">
            <Shield size={23} />
          </div>
          <div>
            <div className="brand-name">SENTINEL</div>
            <div className="brand-subtitle">SECURITY OPERATIONS</div>
          </div>
        </div>

        <div className="workspace-label">WORKSPACE</div>

        <nav className="nav-menu">
          <a className="nav-item active" href="#overview">
            <Activity size={18} />
            Overview
          </a>
          <a className="nav-item" href="#events">
            <CircleDot size={18} />
            Event explorer
          </a>
          <a className="nav-item" href="#alerts">
            <ShieldAlert size={18} />
            Alert management
            {openAlerts.length > 0 && (
              <span className="nav-count">{openAlerts.length}</span>
            )}
          </a>
        </nav>

        <div className="sidebar-bottom">
          <div className="system-card">
            <div className="system-card-top">
              <span className="status-dot" />
              <span>LOCAL ENVIRONMENT</span>
            </div>
            <p>API monitoring enabled</p>
            <span className="system-muted">Refresh interval: 15 seconds</span>
          </div>

          <div className="sidebar-footer">
            <ShieldCheck size={16} />
            <span>Built for defensive security</span>
          </div>
        </div>
      </aside>

      <section className="main-content" id="overview">
        <header className="topbar">
          <div>
            <div className="breadcrumb">Security / Overview</div>
            <h1>Security overview</h1>
            <p className="page-description">
              Monitor incoming events and investigate detected threats.
            </p>
          </div>

          <div className="topbar-actions">
            <div className="connection-pill">
              <Wifi size={15} />
              <span>API dashboard</span>
            </div>
            <button
              className="refresh-button"
              onClick={() => void loadDashboard()}
              title="Refresh dashboard"
            >
              <RefreshCw size={16} />
              Refresh
            </button>
          </div>
        </header>

        {error && (
          <div className="error-banner" role="alert">
            <AlertTriangle size={18} />
            <div>
              <strong>API request failed</strong>
              <p>{error}</p>
              <span>
                Check that FastAPI is running at http://127.0.0.1:8000 and
                that its endpoints return JSON arrays where expected.
              </span>
            </div>
          </div>
        )}

        <div className="section-heading">
          <div>
            <h2>Environment status</h2>
            <p>Security telemetry from your local SENTINEL backend</p>
          </div>
          <div className="updated-label">
            <Clock3 size={14} />
            {lastUpdated
              ? `Updated ${lastUpdated.toLocaleTimeString()}`
              : 'Waiting for API'}
          </div>
        </div>

        <section className="metrics-grid">
          <MetricCard
            label="Total events"
            value={totalEvents}
            note="Recorded security telemetry"
            icon={<Activity size={20} />}
            tone="blue"
          />
          <MetricCard
            label="Open alerts"
            value={openAlertCount}
            note="Require investigation"
            icon={<AlertTriangle size={20} />}
            tone="orange"
          />
          <MetricCard
            label="Critical alerts"
            value={criticalCount}
            note="Critical severity"
            icon={<ShieldAlert size={20} />}
            tone="red"
          />
          <MetricCard
            label="Loaded events"
            value={events.length}
            note="Latest API result"
            icon={<CheckCircle2 size={20} />}
            tone="green"
          />
        </section>

        <section className="dashboard-grid">
          <article className="panel chart-panel">
            <div className="panel-header">
              <div>
                <h2>Event activity</h2>
                <p>Events grouped by timestamp from the latest results</p>
              </div>
              <span className="panel-icon">
                <Activity size={17} />
              </span>
            </div>

            {chartData.length > 0 ? (
              <div className="chart-container">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart
                    data={chartData}
                    margin={{ top: 12, right: 12, left: -18, bottom: 0 }}
                  >
                    <CartesianGrid
                      strokeDasharray="3 3"
                      stroke="var(--border)"
                      vertical={false}
                    />
                    <XAxis
                      dataKey="time"
                      tick={{ fill: 'var(--muted)', fontSize: 11 }}
                      axisLine={false}
                      tickLine={false}
                    />
                    <YAxis
                      allowDecimals={false}
                      tick={{ fill: 'var(--muted)', fontSize: 11 }}
                      axisLine={false}
                      tickLine={false}
                    />
                    <Tooltip
                      contentStyle={{
                        background: 'var(--panel)',
                        border: '1px solid var(--border)',
                        borderRadius: 10,
                        color: 'var(--text)',
                      }}
                    />
                    <Line
                      type="monotone"
                      dataKey="count"
                      name="Events"
                      stroke="#65a8ff"
                      strokeWidth={2.5}
                      dot={{ r: 3, fill: '#65a8ff' }}
                      activeDot={{ r: 5 }}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <EmptyState
                title={loading ? 'Loading event activity…' : 'No event activity yet'}
                description="Submit security events to the API to populate this chart."
              />
            )}
          </article>

          <article className="panel severity-panel">
            <div className="panel-header">
              <div>
                <h2>Alert severity</h2>
                <p>Breakdown of loaded alerts</p>
              </div>
              <span className="panel-icon">
                <ShieldAlert size={17} />
              </span>
            </div>

            <div className="severity-list">
              {(['critical', 'high', 'medium', 'low'] as const).map(
                (severity) => {
                  const count = alerts.filter(
                    (alert) =>
                      severityClass(alert.severity) === severity,
                  ).length
                  const percentage =
                    alerts.length > 0 ? (count / alerts.length) * 100 : 0

                  return (
                    <div className="severity-row" key={severity}>
                      <div className="severity-label">
                        <span className={`severity-dot ${severity}`} />
                        <span>
                          {severity.charAt(0).toUpperCase() +
                            severity.slice(1)}
                        </span>
                      </div>
                      <div className="severity-track">
                        <div
                          className={`severity-fill ${severity}`}
                          style={{ width: `${percentage}%` }}
                        />
                      </div>
                      <span className="severity-count">{count}</span>
                    </div>
                  )
                },
              )}
            </div>

            <div className="severity-footnote">
              <ShieldCheck size={16} />
              <span>
                {alerts.length
                  ? `${alerts.length} alert${alerts.length === 1 ? '' : 's'} loaded from the API`
                  : 'No alerts returned by the API'}
              </span>
            </div>
          </article>
        </section>

        <section className="panel table-panel" id="events">
          <div className="panel-header table-panel-header">
            <div>
              <h2>Recent security events</h2>
              <p>Latest recorded events from your backend</p>
            </div>
            <label className="filter-control">
              <span>Severity</span>
              <select
                value={filter}
                onChange={(event) => setFilter(event.target.value)}
              >
                <option value="all">All severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </label>
          </div>

          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Event</th>
                  <th>Severity</th>
                  <th>Source IP</th>
                  <th>Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {visibleEvents.map((event) => (
                  <tr key={event.id}>
                    <td>
                      <div className="event-cell">
                        <span className="event-icon">
                          <Activity size={16} />
                        </span>
                        <div>
                          <strong>{eventName(event)}</strong>
                          <span>{event.message || 'No event details provided'}</span>
                        </div>
                      </div>
                    </td>
                    <td>
                      <span
                        className={`severity-badge ${severityClass(event.severity)}`}
                      >
                        {event.severity || 'low'}
                      </span>
                    </td>
                    <td className="ip-cell">{event.source_ip || '—'}</td>
                    <td className="time-cell">
                      {formatTime(event.created_at || event.timestamp)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            {!visibleEvents.length && (
              <EmptyState
                title={loading ? 'Loading events…' : 'No matching events'}
                description={
                  filter === 'all'
                    ? 'Send a test event to begin monitoring.'
                    : `No ${filter} severity events are present in the loaded results.`
                }
              />
            )}
          </div>
          <div className="table-footer">
            Showing {visibleEvents.length} of {events.length} loaded events
          </div>
        </section>

        <section className="panel table-panel alerts-panel" id="alerts">
          <div className="panel-header">
            <div>
              <h2>Alert management</h2>
              <p>Review alerts and acknowledge incidents you have investigated</p>
            </div>
            <span className="open-alert-label">
              {openAlerts.length} open
            </span>
          </div>

          {alerts.length > 0 ? (
            <div className="alert-list">
              {alerts.map((alert) => {
                const isOpen =
                  (alert.status || 'open').toLowerCase() === 'open'

                return (
                  <article className="alert-item" key={alert.id}>
                    <div
                      className={`alert-symbol ${severityClass(alert.severity)}`}
                    >
                      <AlertTriangle size={19} />
                    </div>
                    <div className="alert-details">
                      <div className="alert-title-row">
                        <h3>{alertName(alert)}</h3>
                        <span
                          className={`severity-badge ${severityClass(alert.severity)}`}
                        >
                          {alert.severity || 'low'}
                        </span>
                      </div>
                      <p>
                        {alert.description || 'No description provided.'}
                      </p>
                      <div className="alert-meta">
                        <span>{alert.rule_id || `Alert #${alert.id}`}</span>
                        <span>{alert.source_ip || 'Source IP unavailable'}</span>
                        <span>{formatTime(alert.created_at)}</span>
                      </div>
                    </div>
                    <div className="alert-action">
                      {isOpen ? (
                        <button
                          className="ack-button"
                          disabled={busyAlert === alert.id}
                          onClick={() => void acknowledgeAlert(alert.id)}
                        >
                          <CheckCircle2 size={15} />
                          {busyAlert === alert.id
                            ? 'Saving…'
                            : 'Acknowledge'}
                        </button>
                      ) : (
                        <span className="acknowledged">
                          <CheckCircle2 size={15} />
                          {alert.status || 'Acknowledged'}
                        </span>
                      )}
                    </div>
                  </article>
                )
              })}
            </div>
          ) : (
            <EmptyState
              title={loading ? 'Loading alerts…' : 'No alerts detected'}
              description="Alerts created by the detection rules will appear here."
            />
          )}
        </section>

        <footer className="page-footer">
          <span>SENTINEL · Defensive Security Monitoring</span>
          <span>
            <span className="status-dot" />{' '}
            {error ? 'Connection needs attention' : 'Dashboard active'}
          </span>
        </footer>
      </section>
    </main>
  )
}

function MetricCard({
  label,
  value,
  note,
  icon,
  tone,
}: {
  label: string
  value: number
  note: string
  icon: React.ReactNode
  tone: string
}) {
  return (
    <article className="metric-card">
      <div className="metric-top">
        <span className="metric-label">{label}</span>
        <span className={`metric-icon ${tone}`}>{icon}</span>
      </div>
      <div className="metric-value">{value.toLocaleString()}</div>
      <div className="metric-note">
        {value > 0 ? (
          <ArrowUpRight size={14} />
        ) : (
          <ArrowDownRight size={14} />
        )}
        <span>{note}</span>
      </div>
    </article>
  )
}

function EmptyState({
  title,
  description,
}: {
  title: string
  description: string
}) {
  return (
    <div className="empty-state">
      <div className="empty-icon">
        <CircleDot size={22} />
      </div>
      <strong>{title}</strong>
      <p>{description}</p>
    </div>
  )
}

export default App