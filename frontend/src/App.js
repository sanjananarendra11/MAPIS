import { useCallback, useEffect, useMemo, useState } from "react";
import { motion } from "framer-motion";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Bell,
  CalendarDays,
  CheckCircle2,
  ChevronDown,
  Database,
  Download,
  FileClock,
  FileText,
  Filter,
  Gauge,
  Globe2,
  HelpCircle,
  KeyRound,
  LayoutDashboard,
  Lock,
  LogIn,
  LogOut,
  Mail,
  Plus,
  Radar,
  Search,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  User,
  UserPlus,
  Users,
  X,
  XCircle
} from "lucide-react";
import {
  Area,
  AreaChart as ReAreaChart,
  Bar,
  BarChart as ReBarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart as RePieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";
import { ToastContainer, toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import "./App.css";

const API_BASE = process.env.REACT_APP_API_BASE || "http://127.0.0.1:5001";

const fallbackDashboard = {
  stats: {
    totalUsers: 0,
    totalUrlsScanned: 0,
    safeUrls: 0,
    suspiciousUrls: 0,
    dangerousUrls: 0,
    todaysScans: 0,
    weeklyScans: 0,
    totalThreats: 0,
    emailsScanned: 0,
    urlsAnalyzed: 0,
    suspiciousCases: 0,
    safeResults: 0,
    totalScans: 0,
    activeSessions: 0
  },
  threatsOverTime: [],
  dailyScans: [],
  monthlyScans: [],
  detectionTrends: [],
  topPhishingDomains: [],
  distribution: {
    dangerous: 0,
    suspicious: 0,
    safe: 0
  },
  attackTypes: [],
  alerts: [],
  history: [],
  blacklist: [],
  userUrlCounts: []
};

const navItems = [
  { label: "Dashboard", icon: LayoutDashboard },
  { label: "Analyze", icon: Search },
  { label: "Real-time Alerts", icon: Bell },
  { label: "History / Logs", icon: FileClock },
  { label: "Blacklist Manager", icon: ShieldAlert, adminOnly: true },
  { label: "Model Performance", icon: Activity },
  { label: "Reports", icon: BarChart3 },
  { label: "Settings", icon: Settings },
  { label: "Help & Support", icon: HelpCircle }
];

function formatNumber(value) {
  return Number(value || 0).toLocaleString("en-US");
}

function formatPercent(value) {
  if (value === undefined || value === null || Number.isNaN(Number(value))) {
    return "Not available";
  }
  return `${Number(value).toFixed(2)}%`;
}

function formatAxis(value) {
  if (value >= 1000) return `${Math.round(value / 1000)}K`;
  return String(value);
}

function resultClass(result) {
  return String(result || "Safe").toLowerCase();
}

function formatScanTime(scan) {
  const timestamp = scan?.timestamp || scan?.scannedAt;

  if (!timestamp) return scan?.time || "Unknown";

  const date = new Date(timestamp);

  if (Number.isNaN(date.getTime())) {
    return scan?.time || "Unknown";
  }

  return date.toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit"
  });
}

function getRiskTone(score) {
  if (score >= 80) return "danger";
  if (score >= 40) return "warning";
  return "safe";
}

function getThreatLevel(score) {
  if (score >= 80) return "High Risk";
  if (score >= 40) return "Medium Risk";
  return "Low Risk";
}

function normalizeInput(value, type) {
  if (type === "Email") return value.trim();
  const trimmed = value.trim();
  if (!trimmed) return "";
  return trimmed.startsWith("http") ? trimmed : `https://${trimmed}`;
}

function downloadFile(filename, content, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function IconBadge({ tone = "blue", children, size = "normal" }) {
  return <span className={`icon-badge ${tone} ${size}`}>{children}</span>;
}

function Panel({ title, action, children, className = "" }) {
  return (
    <motion.section
      className={`panel ${className}`}
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.22 }}
    >
      {(title || action) && (
        <div className="panel-header">
          {title && <h2>{title}</h2>}
          {action}
        </div>
      )}
      {children}
    </motion.section>
  );
}

function PageHeader({ title, description, action }) {
  return (
    <div className="view-header">
      <div>
        <h2>{title}</h2>
        <p>{description}</p>
      </div>
      {action}
    </div>
  );
}

function StatCard({ label, value, detail, tone, icon, onClick }) {
  const CardIcon = icon;
  const content = (
    <>
      <IconBadge tone={tone}>
        <CardIcon />
      </IconBadge>
      <div className="stat-copy">
        <strong>{formatNumber(value)}</strong>
        <span>{label}</span>
        <small>{detail}</small>
      </div>
    </>
  );

  if (onClick) {
    return (
      <motion.button
        className={`stat-card ${tone} clickable`}
        type="button"
        onClick={onClick}
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.2 }}
        whileHover={{ y: -2 }}
      >
        {content}
      </motion.button>
    );
  }

  return (
    <motion.article
      className={`stat-card ${tone}`}
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.2 }}
      whileHover={{ y: -2 }}
    >
      {content}
    </motion.article>
  );
}

function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="chart-tooltip">
      <strong>{label || payload[0]?.payload?.name}</strong>
      <span>{formatNumber(payload[0].value)}</span>
    </div>
  );
}

function MiniLineChart({ data, dataKey = "threats", xKey = "day", color = "#ef4444" }) {
  if (!data.length || !data.some((item) => Number(item[dataKey]) > 0)) {
    return <div className="chart-empty">No recorded data for this chart yet.</div>;
  }

  return (
    <div className="chart-wrap">
      <ResponsiveContainer
        width="100%"
        height={238}
        minWidth={1}
        minHeight={1}
        initialDimension={{ width: 480, height: 238 }}
      >
        <ReAreaChart data={data} margin={{ top: 10, right: 12, bottom: 4, left: 2 }}>
          <defs>
            <linearGradient id={`fill-${dataKey}`} x1="0" x2="0" y1="0" y2="1">
              <stop offset="0%" stopColor={color} stopOpacity={0.34} />
              <stop offset="100%" stopColor={color} stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid vertical={false} stroke="rgba(148,163,184,0.1)" />
          <XAxis
            dataKey={xKey}
            stroke="#94a3b8"
            axisLine={false}
            tickLine={false}
            tick={{ fontSize: 11 }}
            tickMargin={10}
          />
          <YAxis
            width={42}
            stroke="#94a3b8"
            axisLine={false}
            tickLine={false}
            tick={{ fontSize: 11 }}
            tickMargin={8}
            tickFormatter={formatAxis}
          />
          <Tooltip content={<ChartTooltip />} />
          <Area
            type="monotone"
            dataKey={dataKey}
            stroke={color}
            strokeWidth={3}
            fill={`url(#fill-${dataKey})`}
            dot={{ r: 4, fill: color, stroke: "#0b1220", strokeWidth: 2 }}
            activeDot={{ r: 6 }}
          />
        </ReAreaChart>
      </ResponsiveContainer>
    </div>
  );
}

function DistributionChart({ distribution }) {
  const dangerous = Number(distribution.dangerous || distribution.phishing || 0);
  const suspicious = Number(distribution.suspicious || 0);
  const safe = Number(distribution.safe || 0);
  const total = dangerous + suspicious + safe;
  const data = [
    { name: "Dangerous", value: dangerous, color: "#ef4444" },
    { name: "Suspicious", value: suspicious, color: "#f59e0b" },
    { name: "Safe", value: safe, color: "#22c55e" }
  ];

  if (total === 0) {
    return <div className="chart-empty">No completed scans to distribute yet.</div>;
  }

  return (
    <div className="distribution-grid">
      <div className="donut-chart">
        <ResponsiveContainer
          width="100%"
          height="100%"
          minWidth={1}
          minHeight={1}
          initialDimension={{ width: 142, height: 142 }}
        >
          <RePieChart>
            <Pie
              data={data}
              dataKey="value"
              nameKey="name"
              innerRadius="61%"
              outerRadius="84%"
              paddingAngle={1}
              stroke="transparent"
            >
              {data.map((entry) => (
                <Cell key={entry.name} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip content={<ChartTooltip />} />
          </RePieChart>
        </ResponsiveContainer>
        <div className="donut-label">
          <span>Total</span>
          <strong>{formatNumber(total)}</strong>
        </div>
      </div>
      <div className="legend">
        {data.map((entry) => (
          <LegendItem
            key={entry.name}
            color={entry.color}
            label={entry.name}
            value={entry.value}
            total={total}
          />
        ))}
      </div>
    </div>
  );
}

function LegendItem({ color, label, value, total }) {
  const pct = Math.round((value / total) * 100);
  return (
    <div className="legend-item">
      <span className="dot" style={{ backgroundColor: color }} />
      <div>
        <strong>{label}</strong>
        <small>
          {pct}% ({formatNumber(value)})
        </small>
      </div>
    </div>
  );
}

function DetectionTrendChart({ data }) {
  if (!data.length || !data.some((item) => (
    Number(item.safe) + Number(item.suspicious) + Number(item.dangerous)
  ) > 0)) {
    return <div className="chart-empty">No detection trend data recorded yet.</div>;
  }

  return (
    <div className="chart-wrap compact">
      <ResponsiveContainer
        width="100%"
        height={238}
        minWidth={1}
        minHeight={1}
        initialDimension={{ width: 480, height: 238 }}
      >
        <ReBarChart data={data} margin={{ top: 10, right: 8, left: 2, bottom: 4 }}>
          <CartesianGrid vertical={false} stroke="rgba(148,163,184,0.1)" />
          <XAxis
            dataKey="day"
            stroke="#94a3b8"
            axisLine={false}
            tickLine={false}
            tick={{ fontSize: 11 }}
            tickMargin={9}
          />
          <YAxis
            width={42}
            stroke="#94a3b8"
            axisLine={false}
            tickLine={false}
            tick={{ fontSize: 11 }}
            tickFormatter={formatAxis}
          />
          <Tooltip content={<ChartTooltip />} />
          <Bar dataKey="safe" stackId="a" radius={[0, 0, 0, 0]} fill="#22c55e" />
          <Bar dataKey="suspicious" stackId="a" radius={[0, 0, 0, 0]} fill="#f59e0b" />
          <Bar dataKey="dangerous" stackId="a" radius={[6, 6, 0, 0]} fill="#ef4444" />
        </ReBarChart>
      </ResponsiveContainer>
    </div>
  );
}

function AttackBarChart({ data }) {
  if (!data.length || !data.some((item) => Number(item.value) > 0)) {
    return <div className="chart-empty">No detected attack categories yet.</div>;
  }

  const compactData = data.map((item) => ({
    ...item,
    shortName:
      item.name === "Malicious URL"
        ? "URL"
        : item.name === "Dangerous URL"
          ? "Danger"
        : item.name === "Attachments"
          ? "Files"
          : item.name
  }));

  return (
    <div className="chart-wrap compact">
      <ResponsiveContainer
        width="100%"
        height={238}
        minWidth={1}
        minHeight={1}
        initialDimension={{ width: 480, height: 238 }}
      >
        <ReBarChart data={compactData} margin={{ top: 10, right: 8, left: 2, bottom: 4 }}>
          <CartesianGrid vertical={false} stroke="rgba(148,163,184,0.1)" />
          <XAxis
            dataKey="shortName"
            stroke="#94a3b8"
            axisLine={false}
            tickLine={false}
            tick={{ fontSize: 11 }}
            tickMargin={9}
            interval={0}
          />
          <YAxis
            width={42}
            stroke="#94a3b8"
            axisLine={false}
            tickLine={false}
            tick={{ fontSize: 11 }}
            tickMargin={8}
            tickFormatter={formatAxis}
          />
          <Tooltip content={<ChartTooltip />} />
          <Bar dataKey="value" radius={[6, 6, 0, 0]} maxBarSize={42}>
            {compactData.map((item, index) => (
              <Cell
                key={item.name}
                fill={["#ef4444", "#3b82f6", "#f59e0b", "#8b5cf6"][index % 4]}
              />
            ))}
          </Bar>
        </ReBarChart>
      </ResponsiveContainer>
    </div>
  );
}

function FeatureImportanceChart({ data }) {
  const chartData = (data || []).slice(0, 7).map((item) => ({
    ...item,
    shortName: item.feature.replaceAll("_", " ")
  }));

  if (!chartData.length || !chartData.some((item) => Number(item.importance) > 0)) {
    return <div className="chart-empty">Model feature importance data is unavailable.</div>;
  }

  return (
    <div className="chart-wrap compact">
      <ResponsiveContainer
        width="100%"
        height={260}
        minWidth={1}
        minHeight={1}
        initialDimension={{ width: 560, height: 260 }}
      >
        <ReBarChart
          data={chartData}
          layout="vertical"
          margin={{ top: 6, right: 16, bottom: 4, left: 90 }}
        >
          <CartesianGrid horizontal={false} stroke="rgba(148,163,184,0.1)" />
          <XAxis
            type="number"
            stroke="#94a3b8"
            axisLine={false}
            tickLine={false}
            tick={{ fontSize: 11 }}
            tickFormatter={(value) => `${value}%`}
          />
          <YAxis
            type="category"
            dataKey="shortName"
            width={88}
            stroke="#94a3b8"
            axisLine={false}
            tickLine={false}
            tick={{ fontSize: 11 }}
          />
          <Tooltip
            content={({ active, payload }) => {
              if (!active || !payload?.length) return null;
              const item = payload[0].payload;
              return (
                <div className="chart-tooltip">
                  <strong>{item.shortName}</strong>
                  <span>{Number(item.importance).toFixed(2)}%</span>
                </div>
              );
            }}
          />
          <Bar dataKey="importance" radius={[0, 6, 6, 0]} maxBarSize={22} fill="#3b82f6" />
        </ReBarChart>
      </ResponsiveContainer>
    </div>
  );
}

function RiskMeter({ value, label }) {
  const tone = getRiskTone(value);

  return (
    <div className={`risk-meter ${tone}`}>
      <div
        className="risk-ring"
        style={{
          background: `conic-gradient(var(--meter-color) ${value * 3.6}deg, rgba(148, 163, 184, 0.13) 0deg)`
        }}
      >
        <div className="risk-core">
          <strong>{value}%</strong>
          <span>Risk Score</span>
        </div>
      </div>
      <b>{label}</b>
    </div>
  );
}

function AlertIcon({ alert }) {
  const tone = alert.severity === "Low" ? "green" : alert.severity === "Medium" ? "amber" : "red";
  return (
    <IconBadge tone={tone} size="small">
      {alert.severity === "Low" ? (
        <CheckCircle2 />
      ) : alert.message.includes("Email") ? (
        <Mail />
      ) : (
        <AlertTriangle />
      )}
    </IconBadge>
  );
}

function AlertsPanel({ alerts, onViewAll }) {
  return (
    <Panel
      title="Real-time Alerts"
      action={
        <button className="ghost-button" onClick={onViewAll}>
          View All
        </button>
      }
      className="alerts-panel"
    >
      <div className="alert-list">
        {alerts.slice(0, 5).map((alert) => (
          <div className={`alert-row ${String(alert.severity).toLowerCase()}`} key={alert.id}>
            <AlertIcon alert={alert} />
            <div className="alert-copy">
              <div className="alert-title-line">
                <strong>{alert.message}</strong>
                <time>{alert.time}</time>
              </div>
              <span>{alert.detail}</span>
              <small>{alert.severity}</small>
            </div>
          </div>
        ))}
        {alerts.length === 0 && <div className="empty-state compact">No threat alerts recorded.</div>}
      </div>
    </Panel>
  );
}

function DetectionDetails({ result }) {
  if (!result) {
    return (
      <Panel title="Detection Details" className="details-panel">
        <div className="analysis-empty">
          <Search />
          <strong>No analysis selected</strong>
          <span>Run a URL or email scan to view measured risk indicators.</span>
        </div>
      </Panel>
    );
  }

  const analysis = result;
  const risk = Number(analysis.risk_score || 0);
  const visibleRows = Object.entries(analysis.layer1 || {}).slice(0, 7);

  return (
    <Panel title="Detection Details" className="details-panel">
      <div className="scan-target">
        <span title={analysis.url}>{analysis.url}</span>
        <b className={resultClass(analysis.prediction)}>{analysis.prediction}</b>
      </div>
      <div className="details-body">
        <RiskMeter value={risk} label={getThreatLevel(risk)} />
        <div className="detail-rows">
          {visibleRows.map(([key, value]) => (
            <div className="detail-row" key={key}>
              <span>{key}</span>
              <strong>{String(value)}</strong>
            </div>
          ))}
        </div>
      </div>
    </Panel>
  );
}

function MultilayerAnalysis({ result }) {
  if (!result) {
    return (
      <Panel title="Multilayer Analysis" className="multilayer-panel">
        <div className="analysis-empty">
          <Radar />
          <strong>No layer results available</strong>
          <span>The five detection layers populate after an actual analysis.</span>
        </div>
      </Panel>
    );
  }

  const analysis = result;
  const isSafe = analysis.prediction === "Safe";
  const isDangerous = analysis.prediction === "Dangerous";
  const layers = [
    {
      title: "Layer 1: URL Analysis",
      subtitle: "Detects suspicious URL patterns and domain characteristics.",
      status: isSafe ? "Safe" : analysis.prediction,
      tone: isSafe ? "green" : isDangerous ? "red" : "amber"
    },
    {
      title: "Layer 2: ML Analysis",
      subtitle: "Uses a Random Forest model to classify websites from extracted URL features.",
      status: isSafe ? "Safe" : analysis.prediction,
      tone: isSafe ? "green" : isDangerous ? "red" : "amber"
    },
    {
      title: "Layer 3: Website Behavior Analysis",
      subtitle: "Examines webpage structure and form actions.",
      status: analysis.risk_score >= 60 ? "Suspicious" : "Normal",
      tone: analysis.risk_score >= 60 ? "amber" : "green"
    },
    {
      title: "Layer 4: Content Analysis",
      subtitle: "Uses NLP techniques to analyze message or email content.",
      status: analysis.risk_score >= 40 ? "Risk Found" : "Clear",
      tone: analysis.risk_score >= 40 ? "amber" : "green"
    },
    {
      title: "Layer 5: Sender Reputation Analysis",
      subtitle: "Evaluates domain and IP reputation.",
      status: isSafe ? "Trusted" : "Poor",
      tone: isSafe ? "green" : isDangerous ? "red" : "amber"
    }
  ];

  return (
    <Panel title="Multilayer Analysis" className="multilayer-panel">
      <div className="layer-list">
        {layers.map((layer) => (
          <div className="layer-row" key={layer.title}>
            <IconBadge tone={layer.tone} size="tiny">
              {layer.tone === "green" ? <CheckCircle2 /> : <XCircle />}
            </IconBadge>
            <div className="layer-copy">
              <strong>{layer.title}</strong>
              <span>{layer.subtitle}</span>
            </div>
            <b className={`status-chip ${layer.tone}`}>{layer.status}</b>
          </div>
        ))}
      </div>
      <div className={`final-result ${resultClass(analysis.prediction)}`}>
        <IconBadge tone={isSafe ? "green" : isDangerous ? "red" : "amber"} size="small">
          {isSafe ? <ShieldCheck /> : <ShieldAlert />}
        </IconBadge>
        <div>
          <span>Final Result</span>
          <strong>
            {isSafe ? "SAFE WEBSITE" : isDangerous ? "DANGEROUS WEBSITE" : "SUSPICIOUS WEBSITE"}
          </strong>
        </div>
      </div>
    </Panel>
  );
}

function ScanTable({ history, title = "Recent Scans / History", limit = 7 }) {
  const [typeFilter, setTypeFilter] = useState("All");
  const [statusFilter, setStatusFilter] = useState("All");

  const rows = history
    .filter((scan) => typeFilter === "All" || scan.type === typeFilter)
    .filter((scan) => statusFilter === "All" || scan.result === statusFilter)
    .slice(0, limit);

  return (
    <Panel title={title} className="history-panel">
      <div className="table-filters">
        <label>
          <CalendarDays />
          <select aria-label="Date range" defaultValue="All Dates">
            <option>All Dates</option>
            <option>Today</option>
            <option>This Week</option>
          </select>
        </label>
        <label>
          <Filter />
          <select
            aria-label="Scan type"
            value={typeFilter}
            onChange={(event) => setTypeFilter(event.target.value)}
          >
            <option value="All">All Types</option>
            <option value="URL">URL</option>
            <option value="Email">Email</option>
          </select>
        </label>
        <label>
          <ShieldCheck />
          <select
            aria-label="Scan status"
            value={statusFilter}
            onChange={(event) => setStatusFilter(event.target.value)}
          >
            <option value="All">All Statuses</option>
            <option value="Dangerous">Dangerous</option>
            <option value="Suspicious">Suspicious</option>
            <option value="Safe">Safe</option>
          </select>
        </label>
      </div>
      <div className="scan-table">
        <div className="table-head">
          <span>Type</span>
          <span>URL</span>
          <span>Result</span>
          <span>Risk Score</span>
          <span>Reason</span>
          <span>Time</span>
        </div>
        {rows.map((scan) => (
          <div className="table-row" key={scan.id}>
            <IconBadge tone={scan.type === "Email" ? "purple" : "blue"} size="tiny">
              {scan.type === "Email" ? <Mail /> : <Globe2 />}
            </IconBadge>
            <span title={scan.url || scan.input}>{scan.url || scan.input}</span>
            <b className={resultClass(scan.result)}>{scan.result}</b>
            <strong className={resultClass(scan.result)}>{scan.riskScore}%</strong>
            <span title={scan.aiExplanation || scan.reason}>{scan.reason || scan.threatType || "Recorded scan"}</span>
            <time>{formatScanTime(scan)}</time>
          </div>
        ))}
        {rows.length === 0 && <div className="empty-state">No scans match these filters.</div>}
      </div>
    </Panel>
  );
}

function SystemStatus({ modelMetrics, stats }) {
  return (
    <section className="status-strip">
      <div>
        <span className="pulse" />
        <span>Runtime Status</span>
        <strong>Online</strong>
      </div>
      <div>
        <Gauge />
        <span>ML Model Accuracy</span>
        <strong>{modelMetrics ? `${modelMetrics.accuracy.toFixed(2)}%` : "Loading"}</strong>
      </div>
      <div>
        <Database />
        <span>Scan Storage</span>
        <strong>{formatNumber(stats.totalScans)} records</strong>
      </div>
      <div>
        <Radar />
        <span>Threat Source</span>
        <strong>Local model</strong>
      </div>
      <div>
        <Users />
        <span>Active Sessions</span>
        <strong>{formatNumber(stats.activeSessions)}</strong>
      </div>
    </section>
  );
}

function DashboardView({ cards, dashboard, result, onNavigate, isAdmin }) {
  const dailyData = dashboard.dailyScans || fallbackDashboard.dailyScans;
  const monthlyData = dashboard.monthlyScans || fallbackDashboard.monthlyScans;
  const detectionData = dashboard.detectionTrends || fallbackDashboard.detectionTrends;
  const phishingDomains = dashboard.topPhishingDomains || fallbackDashboard.topPhishingDomains;

  return (
    <>
      <section className="stat-grid">
        {cards.map((card) => (
          <StatCard key={card.label} {...card} />
        ))}
      </section>

      <section className="analytics-grid">
        <Panel
          title="Daily Scans"
          action={
            <label className="compact-select">
              <CalendarDays />
              <select aria-label="Threat chart period" defaultValue="This Week">
                <option>This Week</option>
                <option>Last Week</option>
                <option>This Month</option>
              </select>
            </label>
          }
          className="wide-panel"
        >
          <MiniLineChart
            data={dailyData}
            dataKey="scans"
            color="#3b82f6"
          />
        </Panel>

        <Panel title="Safe vs Suspicious vs Dangerous">
          <DistributionChart distribution={dashboard.distribution || fallbackDashboard.distribution} />
        </Panel>

        <Panel title="Monthly Scans">
          <MiniLineChart
            data={monthlyData}
            dataKey="scans"
            xKey="month"
            color="#8b5cf6"
          />
        </Panel>
        <Panel title="Top Phishing Domains">
          <AttackBarChart data={phishingDomains} />
        </Panel>
        <Panel title="Detection Trends" className="wide-panel">
          <DetectionTrendChart data={detectionData} />
        </Panel>

        <AlertsPanel
          alerts={dashboard.alerts || fallbackDashboard.alerts}
          onViewAll={() => onNavigate("Real-time Alerts")}
        />
      </section>

      <section className="analysis-grid">
        <DetectionDetails result={result} />
        <MultilayerAnalysis result={result} />
        <ScanTable
          history={dashboard.history || fallbackDashboard.history}
          title={isAdmin ? "Global Scan History" : "My Scan History"}
          limit={isAdmin ? 50 : 12}
        />
      </section>
    </>
  );
}

function AnalyzeView({
  analysisType,
  setAnalysisType,
  query,
  setQuery,
  loading,
  onScan,
  result
}) {
  const [emailDraft, setEmailDraft] = useState({
    sender: "",
    subject: "",
    body: "",
    headers: ""
  });

  const updateEmail = (field, value) => {
    setEmailDraft((current) => ({ ...current, [field]: value }));
  };

  const submitEmail = (event) => {
    event.preventDefault();
    onScan(emailDraft);
  };

  return (
    <div className="view-page">
      <PageHeader
        title="Multilayer Analyzer"
        description="Run URL and email signals through all MAPIS detection layers."
      />
      <Panel className="analyze-tool">
        <div className="analyze-form">
          <div className="analyze-tool-heading">
            <IconBadge tone="blue" size="small">
              <Radar />
            </IconBadge>
            <div>
              <strong>Adaptive Scan</strong>
              <span>URL and email intelligence pipeline</span>
            </div>
          </div>
          <div className="segmented-control" aria-label="Analysis mode">
            {[
              ["URL", Globe2],
              ["Email", Mail]
            ].map(([label, ModeIcon]) => (
              <button
                key={label}
                className={analysisType === label ? "active" : ""}
                onClick={() => setAnalysisType(label)}
              >
                <ModeIcon />
                {label}
              </button>
            ))}
          </div>
          {analysisType === "URL" ? (
            <div className="large-scan-input">
              <Search />
              <input
                aria-label="Analyze input"
                placeholder="https://example.com"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter") onScan();
                }}
              />
              <button className="primary-button" onClick={() => onScan()} disabled={loading}>
                {loading ? "Analyzing..." : "Run Analysis"}
              </button>
            </div>
          ) : (
            <form className="email-analysis-form" onSubmit={submitEmail}>
              <div className="email-field-grid">
                <label>
                  Sender Address
                  <input
                    type="email"
                    value={emailDraft.sender}
                    onChange={(event) => updateEmail("sender", event.target.value)}
                    placeholder="sender@example.com"
                    required
                  />
                </label>
                <label>
                  Subject
                  <input
                    value={emailDraft.subject}
                    onChange={(event) => updateEmail("subject", event.target.value)}
                    placeholder="Email subject"
                  />
                </label>
              </div>
              <label>
                Email Body
                <textarea
                  value={emailDraft.body}
                  onChange={(event) => updateEmail("body", event.target.value)}
                  placeholder="Paste the complete email content"
                  rows={7}
                />
              </label>
              <label>
                Headers
                <textarea
                  value={emailDraft.headers}
                  onChange={(event) => updateEmail("headers", event.target.value)}
                  placeholder="Paste SPF, DKIM, DMARC, and received headers"
                  rows={4}
                />
              </label>
              <button className="primary-button icon-text email-submit" type="submit" disabled={loading}>
                <ShieldCheck />
                {loading ? "Analyzing..." : "Analyze Email"}
              </button>
            </form>
          )}
        </div>
      </Panel>

      <section className="analyze-results-grid">
        <DetectionDetails result={result} />
        <MultilayerAnalysis result={result} />
      </section>

      <Panel title="Detection Reasoning" className="reasoning-panel">
        <div className="reason-grid">
          {(result?.layer3?.explanations || []).map((reason, index) => (
            <div key={reason}>
              <IconBadge tone={index < 2 ? "red" : "amber"} size="tiny">
                <AlertTriangle />
              </IconBadge>
              <span>{reason}</span>
            </div>
          ))}
          {!result && <div className="empty-state compact">No analysis reasoning recorded.</div>}
        </div>
      </Panel>
    </div>
  );
}

function AlertsView({ alerts }) {
  const [severity, setSeverity] = useState("All");
  const filtered = alerts.filter((alert) => severity === "All" || alert.severity === severity);

  return (
    <div className="view-page">
      <PageHeader
        title="Real-time Alerts"
        description="Live detections from browser, email, and threat intelligence layers."
        action={
          <label className="compact-select">
            <Filter />
            <select
              aria-label="Alert severity"
              value={severity}
              onChange={(event) => setSeverity(event.target.value)}
            >
              <option>All</option>
              <option>High</option>
              <option>Medium</option>
              <option>Low</option>
            </select>
          </label>
        }
      />
      <Panel className="alerts-page-panel">
        <div className="alerts-page-list">
          {filtered.map((alert) => (
            <article key={alert.id} className="alert-page-row">
              <AlertIcon alert={alert} />
              <div>
                <strong>{alert.message}</strong>
                <span>{alert.detail}</span>
              </div>
              <b className={`severity-badge ${alert.severity.toLowerCase()}`}>{alert.severity}</b>
              <time>{alert.time}</time>
            </article>
          ))}
        </div>
      </Panel>
    </div>
  );
}

function HistoryView({ history }) {
  return (
    <div className="view-page">
      <PageHeader
        title="History / Logs"
        description="Search and filter URL and email analysis records."
      />
      <ScanTable history={history} title="All Scan Records" limit={50} />
    </div>
  );
}

function AdminUsersView({ counts, onBack }) {
  const rows = counts || [];

  return (
    <div className="view-page">
      <PageHeader
        title="User URL Counts"
        description="Username-level URL scan totals without exposing scanned URLs."
        action={
          <button className="primary-button icon-text" onClick={onBack}>
            <LayoutDashboard />
            Dashboard
          </button>
        }
      />
      <Panel title={`Users (${rows.length})`}>
        <div className="user-count-table">
          <div className="user-count-head">
            <span>Username</span>
            <span>URLs Scanned</span>
          </div>
          {rows.map((row, index) => (
            <div className="user-count-row" key={`${row.name || "user"}-${index}`}>
              <strong>{row.name || "User"}</strong>
              <b>{formatNumber(row.urlsScanned)}</b>
            </div>
          ))}
          {rows.length === 0 && (
            <div className="empty-state">No user URL counts recorded yet.</div>
          )}
        </div>
      </Panel>
    </div>
  );
}

function BlacklistView({ entries, isAdmin, onAdd, onDelete, onRequireLogin }) {
  const [domain, setDomain] = useState("");
  const [reason, setReason] = useState("");

  const submit = async (event) => {
    event.preventDefault();
    if (!isAdmin) {
      onRequireLogin();
      return;
    }
    const created = await onAdd(domain, reason);
    if (created) {
      setDomain("");
      setReason("");
    }
  };

  return (
    <div className="view-page">
      <PageHeader
        title="Blacklist Manager"
        description="Maintain domains blocked by MAPIS threat intelligence."
        action={
          !isAdmin ? (
            <button className="primary-button icon-text" onClick={onRequireLogin}>
              <LogIn />
              Admin Sign In
            </button>
          ) : null
        }
      />
      <Panel title="Add Domain" className="blacklist-form-panel">
        <form className="blacklist-form" onSubmit={submit}>
          <label>
            Domain
            <input
              value={domain}
              onChange={(event) => setDomain(event.target.value)}
              placeholder="suspicious-domain.com"
              required
            />
          </label>
          <label>
            Reason
            <input
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              placeholder="Credential harvesting or impersonation"
              required
            />
          </label>
          <button className="primary-button icon-text" type="submit">
            <Plus />
            Add to Blacklist
          </button>
        </form>
      </Panel>
      <Panel title={`Blocked Domains (${entries.length})`}>
        <div className="blacklist-table">
          <div className="blacklist-head">
            <span>Domain</span>
            <span>Reason</span>
            <span>Added By</span>
            <span>Action</span>
          </div>
          {entries.map((entry) => (
            <div className="blacklist-row" key={entry.id}>
              <strong>{entry.domain}</strong>
              <span>{entry.reason}</span>
              <span>{entry.addedBy}</span>
              <button
                className="danger-icon-button"
                aria-label={`Delete ${entry.domain}`}
                onClick={() => (isAdmin ? onDelete(entry.id) : onRequireLogin())}
              >
                <Trash2 />
              </button>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

function ModelPerformanceView({ modelMetrics }) {
  const matrix = modelMetrics?.confusionMatrix || {};
  const algorithm = modelMetrics?.model?.algorithm || "RandomForestClassifier";
  const evaluated = formatNumber(modelMetrics?.evaluatedSamples || 0);
  const training = modelMetrics?.training || {};
  const metrics = [
    {
      label: "Accuracy",
      value: formatPercent(modelMetrics?.accuracy),
      detail: training.policy ? "Guarded promotion active" : `${evaluated} evaluated rows`,
      tone: "green"
    },
    {
      label: "Precision",
      value: formatPercent(modelMetrics?.precision),
      detail: `Balanced accuracy ${formatPercent(modelMetrics?.balancedAccuracy)}`,
      tone: "blue"
    },
    {
      label: "Recall",
      value: formatPercent(modelMetrics?.recall),
      detail: "Calculated from current model file",
      tone: "purple"
    },
    {
      label: "F1 Score",
      value: formatPercent(modelMetrics?.f1Score),
      detail: algorithm,
      tone: "amber"
    }
  ];

  return (
    <div className="view-page">
      <PageHeader
        title="Model Performance"
        description="Random Forest metrics evaluated from the saved model and dataset."
      />
      <section className="metric-grid">
        {metrics.map((metric) => (
          <Panel key={metric.label} className="metric-card">
            <IconBadge tone={metric.tone}>
              <Gauge />
            </IconBadge>
            <div>
              <span>{metric.label}</span>
              <strong>{metric.value}</strong>
              <small>{metric.detail}</small>
            </div>
          </Panel>
        ))}
      </section>
      <section className="model-grid">
        <Panel title="Feature Importance">
          {modelMetrics ? (
            <FeatureImportanceChart data={modelMetrics.featureImportances || []} />
          ) : (
            <div className="chart-empty">Loading model metrics from the Flask API.</div>
          )}
        </Panel>
        <Panel title="Confusion Matrix">
          {modelMetrics ? (
            <div className="confusion-matrix">
              <div className="matrix-label" />
              <div className="matrix-label">Predicted Safe</div>
              <div className="matrix-label">Predicted Phishing</div>
              <div className="matrix-label">Actual Safe</div>
              <div className="matrix-cell correct"><strong>{formatNumber(matrix.trueNegative)}</strong><span>True Negative</span></div>
              <div className="matrix-cell incorrect"><strong>{formatNumber(matrix.falsePositive)}</strong><span>False Positive</span></div>
              <div className="matrix-label">Actual Phishing</div>
              <div className="matrix-cell incorrect"><strong>{formatNumber(matrix.falseNegative)}</strong><span>False Negative</span></div>
              <div className="matrix-cell correct"><strong>{formatNumber(matrix.truePositive)}</strong><span>True Positive</span></div>
            </div>
          ) : (
            <div className="chart-empty">Loading confusion matrix from the current model.</div>
          )}
        </Panel>
        <Panel title="Learning Guard">
          {modelMetrics ? (
            <div className="learning-guard">
              <div>
                <span>Promotion Policy</span>
                <strong>{training.policy || "Current model metrics are measured from the saved model file."}</strong>
              </div>
              <div>
                <span>Last Candidate</span>
                <strong>{training.promoted === false ? "Rejected" : training.promoted === true ? "Promoted" : "Not recorded"}</strong>
              </div>
              <div>
                <span>Candidate Accuracy</span>
                <strong>{formatPercent(training.candidateMetrics?.accuracy)}</strong>
              </div>
              <div>
                <span>Previous Accuracy</span>
                <strong>{formatPercent(training.previousMetrics?.accuracy)}</strong>
              </div>
            </div>
          ) : (
            <div className="chart-empty">Loading learning guard status.</div>
          )}
        </Panel>
      </section>
    </div>
  );
}

function ReportsView({ dashboard }) {
  const exportJson = () => {
    downloadFile(
      "mapis-threat-report.json",
      JSON.stringify({ generatedAt: new Date().toISOString(), ...dashboard }, null, 2),
      "application/json"
    );
    toast.success("JSON report generated");
  };

  const exportCsv = () => {
    const rows = [
      ["Type", "URL", "Result", "Risk Score", "Reason", "Time"],
      ...(dashboard.history || []).map((scan) => [
        scan.type,
        scan.url || scan.input,
        scan.result,
        scan.riskScore,
        scan.reason || scan.threatType || "",
        formatScanTime(scan)
      ])
    ];
    const csv = rows
      .map((row) => row.map((value) => `"${String(value).replaceAll('"', '""')}"`).join(","))
      .join("\n");
    downloadFile("mapis-scan-history.csv", csv, "text/csv");
    toast.success("CSV report generated");
  };

  return (
    <div className="view-page">
      <PageHeader
        title="Reports"
        description="Export current threat analytics and scan records."
      />
      <section className="report-grid">
        <Panel className="report-card">
          <IconBadge tone="blue"><FileText /></IconBadge>
          <div>
            <h3>Threat Intelligence Report</h3>
            <p>Dashboard metrics, attack distribution, alerts, and blacklist entries.</p>
          </div>
          <button className="primary-button icon-text" onClick={exportJson}>
            <Download />
            Export JSON
          </button>
        </Panel>
        <Panel className="report-card">
          <IconBadge tone="green"><FileClock /></IconBadge>
          <div>
            <h3>Scan History Report</h3>
            <p>URL and email scans with result, score, and recorded time.</p>
          </div>
          <button className="primary-button icon-text" onClick={exportCsv}>
            <Download />
            Export CSV
          </button>
        </Panel>
      </section>
    </div>
  );
}

function SettingsView() {
  const [settingsState, setSettingsState] = useState(() => {
    const stored = localStorage.getItem("mapis-settings");
    return stored
      ? JSON.parse(stored)
      : {
          liveAlerts: true,
          autoScan: true,
          emailReports: false,
          highRiskOnly: false
        };
  });

  const toggle = (key) => {
    setSettingsState((current) => ({ ...current, [key]: !current[key] }));
  };

  const save = () => {
    localStorage.setItem("mapis-settings", JSON.stringify(settingsState));
    toast.success("Settings saved");
  };

  const options = [
    ["liveAlerts", "Live threat alerts", "Show new detections immediately."],
    ["autoScan", "Automatic browser scanning", "Analyze supported pages through the extension."],
    ["emailReports", "Email report summaries", "Prepare daily summary notifications."],
    ["highRiskOnly", "High-risk notifications only", "Silence safe and medium-risk activity."]
  ];

  return (
    <div className="view-page">
      <PageHeader title="Settings" description="Configure MAPIS monitoring and notification behavior." />
      <Panel className="settings-panel">
        {options.map(([key, title, description]) => (
          <label className="setting-row" key={key}>
            <div>
              <strong>{title}</strong>
              <span>{description}</span>
            </div>
            <input
              type="checkbox"
              checked={settingsState[key]}
              onChange={() => toggle(key)}
            />
            <span className="toggle-control" />
          </label>
        ))}
        <button className="primary-button settings-save" onClick={save}>Save Settings</button>
      </Panel>
    </div>
  );
}

function HelpView() {
  const questions = [
    ["How is a URL scored?", "MAPIS combines URL syntax, HTTPS, brand spoofing, blacklist, content, and ML signals."],
    ["What does Suspicious mean?", "The scan found meaningful risk indicators, but not enough evidence for a phishing verdict."],
    ["How do I use browser protection?", "Load the extension folder in Chrome and keep the Flask API running on port 5001."],
    ["Where is scan history stored?", "MAPIS stores account, guest, scan, alert, and blacklist records in the backend data file."]
  ];

  return (
    <div className="view-page">
      <PageHeader title="Help & Support" description="MAPIS operating guidance and project support." />
      <section className="help-grid">
        <Panel title="Frequently Asked Questions">
          <div className="faq-list">
            {questions.map(([question, answer]) => (
              <details key={question}>
                <summary>{question}<ChevronDown /></summary>
                <p>{answer}</p>
              </details>
            ))}
          </div>
        </Panel>
        <Panel title="System Information" className="system-info-panel">
          <div><span>Frontend</span><strong>React 19</strong></div>
          <div><span>ML API</span><strong>Flask + Random Forest</strong></div>
          <div><span>Extension</span><strong>Manifest V3</strong></div>
          <div><span>Dashboard</span><strong>Recharts + Lucide</strong></div>
        </Panel>
      </section>
    </div>
  );
}

function AuthModal({ open, onClose, onLogin, onSignup, onGuest, error, loading }) {
  const [mode, setMode] = useState("user");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  if (!open) return null;

  const submit = (event) => {
    event.preventDefault();
    if (mode === "signup") {
      onSignup({ name, email, password });
      return;
    }
    onLogin({ email, password });
  };

  const title = mode === "admin"
    ? "Administrator Login"
    : mode === "signup"
      ? "Create Account"
      : "User Login";

  return (
    <div className="modal-backdrop" role="presentation">
      <section className="login-modal" role="dialog" aria-modal="true" aria-labelledby="login-title">
        <button className="modal-close" aria-label="Close login" onClick={onClose}>
          <X />
        </button>
        <div className="login-heading">
          <IconBadge tone={mode === "admin" ? "amber" : "blue"}>
            {mode === "signup" ? <UserPlus /> : <KeyRound />}
          </IconBadge>
          <div>
            <h2 id="login-title">{title}</h2>
            <p>
              {mode === "admin"
                ? "Authenticate to manage protected MAPIS controls."
                : "Use MAPIS with your own saved scan history."}
            </p>
          </div>
        </div>
        <div className="auth-mode-tabs" aria-label="Authentication mode">
          <button
            className={mode === "user" ? "active" : ""}
            onClick={() => setMode("user")}
            type="button"
          >
            <User />
            User
          </button>
          <button
            className={mode === "admin" ? "active" : ""}
            onClick={() => setMode("admin")}
            type="button"
          >
            <ShieldAlert />
            Admin
          </button>
          <button
            className={mode === "signup" ? "active" : ""}
            onClick={() => setMode("signup")}
            type="button"
          >
            <UserPlus />
            Sign Up
          </button>
        </div>
        <form onSubmit={submit} className="login-form">
          {mode === "signup" && (
            <label>
              Name
              <input
                value={name}
                onChange={(event) => setName(event.target.value)}
                autoComplete="name"
                placeholder="Your name"
                required
              />
            </label>
          )}
          <label>
            Email
            <input
              type="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              autoComplete="username"
              placeholder={mode === "admin" ? "admin@mapis.local" : "you@example.com"}
              required
            />
          </label>
          <label>
            Password
            <input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              autoComplete={mode === "signup" ? "new-password" : "current-password"}
              placeholder={mode === "admin" ? "Admin@123" : "At least 6 characters"}
              required
            />
          </label>
          {error && <div className="form-error">{error}</div>}
          <button className="primary-button login-submit" type="submit" disabled={loading}>
            {loading ? "Working..." : mode === "signup" ? "Create Account" : "Sign In"}
          </button>
        </form>
        <button
          className="guest-continue-button"
          onClick={onGuest}
          type="button"
          disabled={loading}
        >
          Continue Without Signup
        </button>
      </section>
    </div>
  );
}

function App() {
  const [dashboard, setDashboard] = useState(fallbackDashboard);
  const [activeView, setActiveView] = useState("Dashboard");
  const [analysisType, setAnalysisType] = useState("URL");
  const [query, setQuery] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [account, setAccount] = useState(null);
  const [authToken, setAuthToken] = useState(() => localStorage.getItem("mapis-token") || "");
  const [loginOpen, setLoginOpen] = useState(false);
  const [loginError, setLoginError] = useState("");
  const [loginLoading, setLoginLoading] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const [modelMetrics, setModelMetrics] = useState(null);

  const scanResult = result;
  const isAdmin = account?.role === "admin";
  const admin = isAdmin ? account : null;
  const visibleNavItems = useMemo(
    () => navItems.filter((item) => !item.adminOnly || isAdmin),
    [isAdmin]
  );

  const cards = useMemo(() => {
    const stats = dashboard.stats || fallbackDashboard.stats;
    if (isAdmin) {
      return [
        {
          label: "Total Users",
          value: stats.totalUsers,
          detail: "Click to view URL counts",
          tone: "blue",
          icon: Users,
          onClick: () => setActiveView("Admin Users")
        },
        {
          label: "Total URLs Scanned",
          value: stats.totalUrlsScanned ?? stats.urlsAnalyzed,
          detail: `${formatNumber(stats.totalScans)} global URL records`,
          tone: "purple",
          icon: Globe2
        },
        {
          label: "Safe URLs",
          value: stats.safeUrls ?? stats.safeResults,
          detail: "No strong phishing indicators",
          tone: "green",
          icon: ShieldCheck
        },
        {
          label: "Suspicious URLs",
          value: stats.suspiciousUrls ?? stats.suspiciousCases,
          detail: "Needs user caution",
          tone: "amber",
          icon: AlertTriangle
        },
        {
          label: "Dangerous URLs",
          value: stats.dangerousUrls,
          detail: "High-risk detections",
          tone: "red",
          icon: ShieldAlert
        },
        {
          label: "Today's Scans",
          value: stats.todaysScans,
          detail: "UTC day window",
          tone: "blue",
          icon: CalendarDays
        },
        {
          label: "Weekly Scans",
          value: stats.weeklyScans,
          detail: "Last seven days",
          tone: "purple",
          icon: Activity
        }
      ];
    }

    return [
      {
        label: "Total URLs Scanned",
        value: stats.totalUrlsScanned ?? stats.urlsAnalyzed,
        detail: `${formatNumber(stats.totalScans)} saved scans`,
        tone: "purple",
        icon: Globe2
      },
      {
        label: "Safe URLs",
        value: stats.safeUrls ?? stats.safeResults,
        detail: "Only your safe URL scans",
        tone: "green",
        icon: ShieldCheck
      },
      {
        label: "Suspicious URLs",
        value: stats.suspiciousUrls ?? stats.suspiciousCases,
        detail: "Only your suspicious scans",
        tone: "amber",
        icon: AlertTriangle
      },
      {
        label: "Dangerous URLs",
        value: stats.dangerousUrls,
        detail: "Only your dangerous scans",
        tone: "red",
        icon: ShieldAlert
      },
      {
        label: "Today's Scans",
        value: stats.todaysScans,
        detail: "Your scans today",
        tone: "blue",
        icon: CalendarDays
      },
      {
        label: "Weekly Scans",
        value: stats.weeklyScans,
        detail: "Your last seven days",
        tone: "purple",
        icon: Activity
      }
    ];
  }, [dashboard, isAdmin]);

  const loadDashboard = useCallback(async (tokenOverride) => {
    try {
      const token = tokenOverride ?? authToken;
      const response = await fetch(`${API_BASE}/api/dashboard`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {}
      });
      if (!response.ok) return;
      const data = await response.json();
      setDashboard((current) => ({
        ...current,
        ...data,
        stats: { ...current.stats, ...(data.stats || {}) }
      }));
    } catch (requestError) {
      console.info("Using local dashboard data:", requestError.message);
    }
  }, [authToken]);

  const loadModelMetrics = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/api/model/metrics`);
      if (!response.ok) return;
      const data = await response.json();
      setModelMetrics(data);
    } catch (requestError) {
      console.info("Model metrics unavailable:", requestError.message);
    }
  }, []);

  useEffect(() => {
    loadDashboard();
  }, [loadDashboard]);

  useEffect(() => {
    const refreshDashboard = () => {
      loadDashboard();
    };
    const refreshWhenVisible = () => {
      if (document.visibilityState === "visible") {
        loadDashboard();
      }
    };
    const dashboardTimer = window.setInterval(refreshDashboard, 5000);

    window.addEventListener("focus", refreshDashboard);
    document.addEventListener("visibilitychange", refreshWhenVisible);

    return () => {
      window.clearInterval(dashboardTimer);
      window.removeEventListener("focus", refreshDashboard);
      document.removeEventListener("visibilitychange", refreshWhenVisible);
    };
  }, [loadDashboard]);

  useEffect(() => {
    loadModelMetrics();
  }, [loadModelMetrics]);

  useEffect(() => {
    if (!authToken) return;

    const loadProfile = async () => {
      try {
        const response = await fetch(`${API_BASE}/api/auth/profile`, {
          headers: { Authorization: `Bearer ${authToken}` }
        });
        if (!response.ok) throw new Error("Session expired");
        const data = await response.json();
        setAccount(data.user);
      } catch (profileError) {
        localStorage.removeItem("mapis-token");
        setAuthToken("");
        setAccount(null);
      }
    };

    loadProfile();
  }, [authToken]);

  useEffect(() => {
    window.postMessage(
      {
        source: "MAPIS_DASHBOARD",
        type: authToken ? "MAPIS_AUTH_TOKEN" : "MAPIS_CLEAR_AUTH_TOKEN",
        token: authToken
      },
      window.location.origin
    );
  }, [authToken]);

  useEffect(() => {
    window.scrollTo({ top: 0, behavior: "smooth" });
  }, [activeView]);

  useEffect(() => {
    const isHiddenAdminView = isAdmin && activeView === "Admin Users";

    if (!isHiddenAdminView && !visibleNavItems.some((item) => item.label === activeView)) {
      setActiveView("Dashboard");
    }
  }, [activeView, isAdmin, visibleNavItems]);

  const persistSession = (token, user) => {
    localStorage.setItem("mapis-token", token);
    setAuthToken(token);
    setAccount(user);
  };

  const startGuestSession = async ({ notify = true } = {}) => {
    const response = await fetch(`${API_BASE}/api/auth/guest`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({})
    });
    const data = await response.json();

    if (!response.ok) throw new Error(data.error || "Could not start guest session");

    persistSession(data.token, data.user);
    if (notify) toast.info("Guest session started");
    return data.token;
  };

  const scanInput = async (payload) => {
    const explicitPayload = payload && typeof payload === "object" && !("nativeEvent" in payload)
      ? payload
      : null;
    const normalized = analysisType === "URL"
      ? normalizeInput(query, analysisType)
      : normalizeInput(explicitPayload?.sender || query, analysisType);

    if (!normalized) {
      setError("Enter a URL or email to analyze.");
      return;
    }

    setLoading(true);
    setError("");

    try {
      const scanToken = authToken || await startGuestSession({ notify: false });
      const endpoint = analysisType === "URL" ? `${API_BASE}/api/scan/url` : `${API_BASE}/api/scan/email`;
      const body = analysisType === "URL"
        ? { url: normalized }
        : {
            sender: normalized,
            subject: explicitPayload?.subject || "",
            body: explicitPayload?.body || "",
            headers: explicitPayload?.headers || ""
          };

      const response = await fetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${scanToken}`
        },
        body: JSON.stringify(body)
      });
      const data = await response.json();

      if (!response.ok || data.error) throw new Error(data.error || "Scan failed");

      setResult(data);

      toast.success(`${analysisType} scan completed`);
      setActiveView("Analyze");
      await loadDashboard(scanToken);
    } catch (scanError) {
      toast.error(scanError.message || "Scan failed");
      setError(scanError.message || "Failed to connect to backend.");
    } finally {
      setLoading(false);
    }
  };

  const loginAccount = async (credentials) => {
    setLoginLoading(true);
    setLoginError("");
    try {
      const response = await fetch(`${API_BASE}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(credentials)
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Login failed");

      persistSession(data.token, data.user);
      await loadDashboard(data.token);
      setLoginOpen(false);
      setProfileOpen(false);
      toast.success(data.user?.role === "admin" ? "Administrator signed in" : "Signed in");
    } catch (loginRequestError) {
      setLoginError(loginRequestError.message || "Login failed");
    } finally {
      setLoginLoading(false);
    }
  };

  const signupAccount = async (credentials) => {
    setLoginLoading(true);
    setLoginError("");
    try {
      const response = await fetch(`${API_BASE}/api/auth/signup`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(credentials)
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Signup failed");

      persistSession(data.token, data.user);
      await loadDashboard(data.token);
      setLoginOpen(false);
      setProfileOpen(false);
      toast.success("Account created");
    } catch (signupError) {
      setLoginError(signupError.message || "Signup failed");
    } finally {
      setLoginLoading(false);
    }
  };

  const continueAsGuest = async () => {
    setLoginLoading(true);
    setLoginError("");
    try {
      const guestToken = await startGuestSession();
      await loadDashboard(guestToken);
      setLoginOpen(false);
      setProfileOpen(false);
    } catch (guestError) {
      setLoginError(guestError.message || "Could not continue as guest");
    } finally {
      setLoginLoading(false);
    }
  };

  const logoutAccount = async () => {
    if (authToken) {
      try {
        await fetch(`${API_BASE}/api/auth/logout`, {
          method: "POST",
          headers: { Authorization: `Bearer ${authToken}` }
        });
      } catch (logoutError) {
        console.info("Logout request failed:", logoutError.message);
      }
    }

    localStorage.removeItem("mapis-token");
    setAuthToken("");
    setAccount(null);
    setProfileOpen(false);
    toast.info("Signed out");
  };

  const addBlacklist = async (domain, reason) => {
    try {
      const response = await fetch(`${API_BASE}/api/blacklist/add`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${authToken}`
        },
        body: JSON.stringify({ domain, reason, addedBy: admin?.name || "admin" })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Could not add domain");
      setDashboard((current) => ({
        ...current,
        blacklist: [data, ...(current.blacklist || [])]
      }));
      toast.success("Domain added to blacklist");
      return true;
    } catch (blacklistError) {
      toast.error(blacklistError.message);
      return false;
    }
  };

  const deleteBlacklist = async (id) => {
    try {
      const response = await fetch(`${API_BASE}/api/blacklist/${encodeURIComponent(id)}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${authToken}` }
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Could not remove domain");
      setDashboard((current) => ({ ...current, blacklist: data.blacklist }));
      toast.success("Domain removed from blacklist");
    } catch (blacklistError) {
      toast.error(blacklistError.message);
    }
  };

  const renderView = () => {
    switch (activeView) {
      case "Analyze":
        return (
          <AnalyzeView
            analysisType={analysisType}
            setAnalysisType={setAnalysisType}
            query={query}
            setQuery={setQuery}
            loading={loading}
            onScan={scanInput}
            result={scanResult}
          />
        );
      case "Real-time Alerts":
        return <AlertsView alerts={dashboard.alerts || fallbackDashboard.alerts} />;
      case "History / Logs":
        return <HistoryView history={dashboard.history || fallbackDashboard.history} />;
      case "Admin Users":
        return isAdmin ? (
          <AdminUsersView
            counts={dashboard.userUrlCounts || fallbackDashboard.userUrlCounts}
            onBack={() => setActiveView("Dashboard")}
          />
        ) : null;
      case "Blacklist Manager":
        return isAdmin ? (
          <BlacklistView
            entries={dashboard.blacklist || fallbackDashboard.blacklist}
            isAdmin={Boolean(admin)}
            onAdd={addBlacklist}
            onDelete={deleteBlacklist}
            onRequireLogin={() => setLoginOpen(true)}
          />
        ) : null;
      case "Model Performance":
        return <ModelPerformanceView modelMetrics={modelMetrics} />;
      case "Reports":
        return <ReportsView dashboard={dashboard} />;
      case "Settings":
        return <SettingsView />;
      case "Help & Support":
        return <HelpView />;
      default:
        return (
          <DashboardView
            cards={cards}
            dashboard={dashboard}
            result={scanResult}
            onNavigate={setActiveView}
            isAdmin={isAdmin}
          />
        );
    }
  };

  return (
    <div className="mapis-app">
      <aside className="sidebar">
        <div className="brand-block">
          <div className="brand-shield">M</div>
          <div>
            <h1>MAPIS</h1>
            <span>Multilayer Adaptive Phishing Intelligence System</span>
          </div>
        </div>

        <nav className="side-nav" aria-label="Main navigation">
          {visibleNavItems.map((item) => {
            const NavIcon = item.icon;
            return (
              <button
                className={activeView === item.label ? "active" : ""}
                key={item.label}
                onClick={() => setActiveView(item.label)}
              >
                <span><NavIcon /></span>
                {item.label}
              </button>
            );
          })}
        </nav>

        <div className="safety-card">
          <div className="mini-shield"><Lock /></div>
          <strong>Stay Smart, Stay Safe</strong>
          <span>Layered protection for URLs, email, ML signals, and blacklists.</span>
        </div>
      </aside>

      <main className="workspace">
        <header className="topbar">
          <div className="mobile-brand">
            <div className="brand-shield">M</div>
            <strong>MAPIS</strong>
          </div>

          <div className="scan-bar">
            <Search className="search-icon" />
            <input
              aria-label="URL or email input"
              placeholder="Enter URL or Email to Analyze..."
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") scanInput();
              }}
            />
            <select
              value={analysisType}
              onChange={(event) => setAnalysisType(event.target.value)}
              aria-label="Analysis type"
            >
              <option>URL</option>
              <option>Email</option>
            </select>
            <button className="primary-button" onClick={scanInput} disabled={loading}>
              {loading ? "Analyzing..." : "Analyze"}
            </button>
          </div>

          <div className="profile-tools">
            <button
              className="icon-button"
              aria-label="Open notifications"
              onClick={() => setActiveView("Real-time Alerts")}
            >
              <Bell />
              <span>{Math.min((dashboard.alerts || []).length, 9)}</span>
            </button>
            <div className="admin-control">
              <button
                className="admin-pill"
                data-testid="admin-control"
                onClick={() => (account ? setProfileOpen((value) => !value) : setLoginOpen(true))}
              >
                <span><User /></span>
                <b>{account?.name || "Sign In"}</b>
                <ChevronDown />
              </button>
              {account && profileOpen && (
                <div className="profile-menu">
                  <strong>{account.name}</strong>
                  <span>{account.email || (account.isGuest ? "Guest session" : account.role)}</span>
                  <small>{account.role === "admin" ? "Administrator" : account.isGuest ? "Guest" : "User"}</small>
                  <button onClick={logoutAccount}><LogOut />Sign Out</button>
                </div>
              )}
            </div>
          </div>
        </header>

        {error && (
          <div className="error-banner">
            <AlertTriangle />
            <span>{error}</span>
            <button aria-label="Dismiss error" onClick={() => setError("")}><X /></button>
          </div>
        )}

        {renderView()}
        <SystemStatus modelMetrics={modelMetrics} stats={dashboard.stats || fallbackDashboard.stats} />
        <ToastContainer position="bottom-right" theme="dark" autoClose={2600} />
      </main>

      <AuthModal
        open={loginOpen}
        onClose={() => {
          setLoginOpen(false);
          setLoginError("");
        }}
        onLogin={loginAccount}
        onSignup={signupAccount}
        onGuest={continueAsGuest}
        error={loginError}
        loading={loginLoading}
      />
    </div>
  );
}

export default App;
