import { useState, useEffect, useRef } from 'react';
import { 
  UploadCloud, 
  Activity, 
  Search, 
  Network, 
  Map, 
  ShieldCheck, 
  FileText,
  AlertTriangle,
  CheckCircle2,
  AlertCircle,
  Download
} from 'lucide-react';
import { 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  Tooltip, 
  ResponsiveContainer,
  Cell
} from 'recharts';
import ReactMarkdown from 'react-markdown';
// @ts-ignore
import html2pdf from 'html2pdf.js';
import './index.css';

const PIPELINE_STAGES = [
  { id: 'UPLOADED', label: 'Upload Telemetry', icon: UploadCloud },
  { id: 'NORMALIZING', label: 'Data Normalization', icon: Activity },
  { id: 'DETECTING', label: 'Detection Agent', icon: Search },
  { id: 'PORT_ANALYSIS', label: 'Port Analyzer', icon: Network },
  { id: 'MITRE_MAPPING', label: 'MITRE Mapping', icon: Map },
  { id: 'VALIDATING', label: 'Validation Layer', icon: ShieldCheck },
  { id: 'REPORTING', label: 'Final Reporting', icon: FileText },
  { id: 'COMPLETE', label: 'Pipeline Complete', icon: CheckCircle2 },
];

export default function App() {
  const [pipelineState, setPipelineState] = useState<string>('IDLE');
  const [traces, setTraces] = useState<any[]>([]);
  const [report, setReport] = useState<any>(null);
  const [reportView, setReportView] = useState<'ui' | 'markdown'>('ui');
  const [isUploading, setIsUploading] = useState(false);
  const traceEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let interval: number;
    if (pipelineState !== 'IDLE' && pipelineState !== 'COMPLETE' && pipelineState !== 'BLOCKED') {
      interval = window.setInterval(fetchState, 1000);
    }
    return () => clearInterval(interval);
  }, [pipelineState]);

  useEffect(() => {
    // Scroll to bottom of traces
    traceEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [traces]);

  const fetchState = async () => {
    try {
      const statusRes = await fetch('http://localhost:8000/api/status');
      const statusData = await statusRes.json();
      
      const tracesRes = await fetch('http://localhost:8000/api/traces');
      const tracesData = await tracesRes.json();
      
      setTraces(tracesData.traces || []);
      
      if (statusData.state !== pipelineState) {
        setPipelineState(statusData.state);
        if (statusData.state === 'COMPLETE') {
          fetchReport();
        }
      }
    } catch (err) {
      console.error("API Error", err);
    }
  };

  const fetchReport = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/report');
      const data = await res.json();
      setReport(data.report);
    } catch (err) {
      console.error("Failed to fetch report", err);
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setIsUploading(true);
    const formData = new FormData();
    formData.append('file', file);

    try {
      await fetch('http://localhost:8000/api/upload', {
        method: 'POST',
        body: formData,
      });
      setPipelineState('UPLOADED');
      // Trigger initial fetch
      fetchState();
    } catch (err) {
      console.error("Upload failed", err);
      alert("Upload failed. Make sure the backend is running.");
    } finally {
      setIsUploading(false);
    }
  };

  const currentStageIndex = PIPELINE_STAGES.findIndex(s => s.id === pipelineState);

  // Chart data processing for findings
  const findingsData = report?.findings ? report.findings.map((f: any) => ({
    name: f.title.substring(0, 30) + '...',
    severityLevel: f.severity.toLowerCase() === 'critical' ? 4 : f.severity.toLowerCase() === 'high' ? 3 : f.severity.toLowerCase() === 'medium' ? 2 : 1,
    fullTitle: f.title
  })) : [];

  const handleDownloadPdf = () => {
    const element = document.getElementById('markdown-report-content');
    if (!element) return;
    
    const opt = {
      margin:       15,
      filename:     'SOC_Agentic_Telemetry_Analysis_Report.pdf',
      image:        { type: 'jpeg', quality: 0.98 },
      html2canvas:  { scale: 2, useCORS: true, backgroundColor: '#1e1e24' },
      jsPDF:        { unit: 'mm', format: 'a4', orientation: 'portrait' }
    };
    
    html2pdf().set(opt).from(element).save();
  };

  return (
    <div className="app-container">
      {/* LEFT COLUMN: Controls & Pipeline */}
      <div className="flex flex-col gap-6">
        <h1 className="text-2xl font-bold mb-2">Agentic SOC Platform</h1>
        
        <div className="glass-panel">
          <h2 className="mb-4 text-lg">Input Telemetry</h2>
          <label className={`upload-zone ${isUploading ? 'opacity-50' : ''}`}>
            <UploadCloud className="upload-icon" />
            <div>
              <p className="font-medium">Upload Zeek NDJSON</p>
              <p className="text-muted mt-1 text-sm">Drag & drop or click to browse</p>
            </div>
            <input 
              type="file" 
              accept=".ndjson,.json" 
              className="hidden" 
              onChange={handleFileUpload} 
              disabled={isUploading || (pipelineState !== 'IDLE' && pipelineState !== 'COMPLETE')}
            />
          </label>
        </div>

        <div className="glass-panel flex-1">
          <h2 className="mb-4 text-lg">Orchestrator State</h2>
          <div className="flex flex-col gap-2">
            {PIPELINE_STAGES.map((stage, idx) => {
              const Icon = stage.icon;
              const isActive = pipelineState === stage.id;
              const isCompleted = currentStageIndex > idx || pipelineState === 'COMPLETE';
              
              return (
                <div 
                  key={stage.id} 
                  className={`pipeline-node ${isActive ? 'active' : ''} ${isCompleted ? 'completed' : ''}`}
                >
                  {idx < PIPELINE_STAGES.length - 1 && <div className="node-connector" />}
                  <Icon className="node-icon w-5 h-5" />
                  <span className={isActive ? 'font-medium' : 'text-muted'}>
                    {stage.label}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* RIGHT COLUMN: Terminal & Report */}
      <div className="flex flex-col gap-6" style={{ height: '100%' }}>
        <div className="glass-panel" style={{ flex: '0 0 350px', display: 'flex', flexDirection: 'column' }}>
          <h2 className="mb-4 text-lg flex items-center justify-between">
            <span>Agent Traces</span>
            <span className="badge badge-medium">{traces.length} Events</span>
          </h2>
          <div className="trace-log flex-1">
            {traces.length === 0 ? (
              <p className="text-muted italic text-center mt-10">Waiting for pipeline events...</p>
            ) : (
              traces.map((t, i) => (
                <div key={i} className="trace-entry">
                  <span className="trace-time">[{new Date(t.timestamp).toLocaleTimeString()}]</span>
                  <div className="trace-msg">
                    <span className="trace-highlight">{t.sender}</span> &rarr; {t.receiver}: 
                    <span className="ml-2 opacity-80">{t.task}</span>
                    {t.fallback_triggered && (
                      <div className="text-xs mt-1 p-2 rounded bg-red-900/40 border border-red-500/50 text-red-200">
                        <AlertTriangle className="inline w-3 h-3 mr-1" />
                        API Failed ({t.result?.api_error || 'No keys or Model Decommissioned'}). Using fallback generator.
                      </div>
                    )}
                    <div className="text-xs mt-1 pl-4 border-l border-gray-700 opacity-60">
                      {t.llm_provider ? `[${t.llm_provider}] ` : ''} 
                      Action: {t.next_action}
                    </div>
                  </div>
                </div>
              ))
            )}
            <div ref={traceEndRef} />
          </div>
        </div>

        <div className="glass-panel flex flex-col" style={{ flex: '1', overflowY: 'hidden' }}>
          <div className="flex justify-between items-center mb-4">
            <h2 className="text-lg">Analyst Report</h2>
            {report && report.markdown_body && (
              <div className="flex gap-2">
                <button 
                  className={`text-xs px-3 py-1 rounded-full ${reportView === 'ui' ? 'bg-indigo-600 text-white' : 'bg-gray-800 text-gray-400'}`}
                  onClick={() => setReportView('ui')}
                >
                  Dashboard View
                </button>
                <button 
                  className={`text-xs px-3 py-1 rounded-full ${reportView === 'markdown' ? 'bg-indigo-600 text-white' : 'bg-gray-800 text-gray-400'}`}
                  onClick={() => setReportView('markdown')}
                >
                  Formal Report
                </button>
                {reportView === 'markdown' && (
                  <button 
                    className="flex items-center gap-1 text-xs px-3 py-1 bg-green-600/80 hover:bg-green-600 text-white rounded-full transition-colors ml-2"
                    onClick={handleDownloadPdf}
                  >
                    <Download className="w-3 h-3" />
                    Download PDF
                  </button>
                )}
              </div>
            )}
          </div>
          
          {!report ? (
            <div className="flex items-center justify-center h-full text-muted">
              {pipelineState === 'IDLE' ? 'Upload telemetry to generate report.' : 'Analyzing telemetry...'}
            </div>
          ) : (
            <div className="flex-1 overflow-y-auto pr-2 pb-4 animate-fade-in">
              {reportView === 'markdown' && report.markdown_body ? (
                <div id="markdown-report-content" className="prose prose-invert max-w-none p-6 bg-gray-900/50 rounded-lg border border-gray-800">
                  <ReactMarkdown>{report.markdown_body}</ReactMarkdown>
                </div>
              ) : (
                <div className="flex flex-col gap-6">
                  <div className="flex gap-4">
                    <div
                      className={`p-4 rounded-lg flex-1 border ${
                        report.risk_level === 'CRITICAL'
                          ? 'border-red-500 bg-red-900/20'
                          : report.risk_level === 'HIGH'
                            ? 'border-orange-500 bg-orange-900/20'
                            : 'border-yellow-500 bg-yellow-900/20'
                      }`}
                    >
                      <div className="text-xs uppercase tracking-wider opacity-70 mb-1">Overall Risk Level</div>
                      <div className="text-2xl font-bold flex items-center gap-2">
                        {report.risk_level === 'CRITICAL' && <AlertTriangle className="text-red-500" />}
                        {report.risk_level}
                      </div>
                    </div>
                    <div className="p-4 rounded-lg flex-1 border border-gray-700 bg-gray-900/40">
                      <div className="text-xs uppercase tracking-wider opacity-70 mb-1">Generated At</div>
                      <div className="text-lg font-medium">{new Date(report.generated_at).toLocaleString()}</div>
                    </div>
                  </div>

                  <div>
                    <h3 className="text-sm uppercase tracking-wider text-muted mb-2">Executive Summary</h3>
                    <p className="leading-relaxed">{report.executive_summary}</p>
                  </div>

                  {findingsData.length > 0 && (
                    <div style={{ height: 160 }} className="mt-2">
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={findingsData} layout="vertical" margin={{ left: 0, right: 0, top: 0, bottom: 0 }}>
                          <XAxis type="number" domain={[0, 4]} hide />
                          <YAxis dataKey="name" type="category" width={30} stroke="var(--text-muted)" fontSize={12} />
                          <Tooltip
                            contentStyle={{ background: '#111827', border: '1px solid #374151', borderRadius: '8px' }}
                            formatter={(val: number) => [val === 4 ? 'Critical' : val === 3 ? 'High' : val === 2 ? 'Medium' : 'Low', 'Severity']}
                          />
                          <Bar dataKey="severityLevel" radius={[0, 4, 4, 0]} barSize={20}>
                            {findingsData.map((entry: any, index: number) => (
                              <Cell
                                key={`cell-${index}`}
                                fill={
                                  entry.severityLevel === 4
                                    ? 'hsl(var(--status-critical))'
                                    : entry.severityLevel === 3
                                      ? 'hsl(var(--status-high))'
                                      : 'hsl(var(--status-medium))'
                                }
                              />
                            ))}
                          </Bar>
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  )}

                  <div className="flex flex-col gap-4">
                    <h3 className="text-sm uppercase tracking-wider text-muted">Detailed Findings ({report.findings?.length || 0})</h3>
                    {report.findings?.map((f: any, idx: number) => (
                      <div key={idx} className="p-4 border border-gray-800 rounded-lg bg-gray-900/20">
                        <div className="flex justify-between items-start mb-2">
                          <div className="font-medium text-lg flex items-center gap-2">
                            {f.status === 'CRITICAL' && <AlertCircle className="w-4 h-4 text-red-500" />}
                            {f.title}
                          </div>
                          <span className={`badge badge-${f.severity?.toLowerCase()}`}>{f.severity}</span>
                        </div>
                        <p className="text-muted text-sm mb-3">{f.description}</p>

                        <div className="grid grid-cols-2 gap-2 text-sm bg-black/20 p-3 rounded">
                          <div><span className="opacity-50">MITRE ID:</span> {f.mitre_technique_id || 'N/A'}</div>
                          <div><span className="opacity-50">Tactic:</span> {f.mitre_tactic || 'N/A'}</div>
                          <div><span className="opacity-50">Validation:</span> {f.status}</div>
                        </div>

                        <div className="mt-3 pt-3 border-t border-gray-800 text-sm">
                          <span className="text-blue-400 font-medium">Next Step:</span> {f.recommended_action}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
    
  );
}
