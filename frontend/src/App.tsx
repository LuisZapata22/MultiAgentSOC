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
  Download,
  Clock
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
import remarkGfm from 'remark-gfm';
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
  { id: 'AWAITING_INPUT', label: 'Awaiting Analyst', icon: Clock },
  { id: 'COMPLETE', label: 'Pipeline Complete', icon: CheckCircle2 },
];

export default function App() {
  const [pipelineState, setPipelineState] = useState<string>('IDLE');
  const [traces, setTraces] = useState<any[]>([]);
  const [report, setReport] = useState<any>(null);
  const [reportView, setReportView] = useState<'ui' | 'markdown'>('ui');
  const [isUploading, setIsUploading] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const traceEndRef = useRef<HTMLDivElement>(null);

  const [elicitation, setElicitation] = useState<any>(null);
  const [elicitationResponses, setElicitationResponses] = useState<Record<string, any>>({});
  const [elicitationTimer, setElicitationTimer] = useState<number>(300);

  useEffect(() => {
    let interval: number;
    if (pipelineState !== 'IDLE' && pipelineState !== 'COMPLETE' && pipelineState !== 'BLOCKED') {
      interval = window.setInterval(fetchState, 1000);
    }
    return () => clearInterval(interval);
  }, [pipelineState, elicitation]);

  useEffect(() => {
    if (!elicitation) return;
    const timer = window.setInterval(() => {
      setElicitationTimer((prev) => {
        if (prev <= 1) {
          clearInterval(timer);
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(timer);
  }, [elicitation]);

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

      if (statusData.state === 'AWAITING_INPUT' && !elicitation) {
        fetchElicitation();
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

  const fetchElicitation = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/elicitation/pending');
      const data = await res.json();
      if (data.pending) {
        setElicitation(data.pending);
        setElicitationTimer(300);
        const defaults: Record<string, any> = {};
        data.pending.fields.forEach((f: any) => {
          if (f.default) defaults[f.name] = f.default;
          if (f.field_type === 'checkbox') defaults[f.name] = false;
        });
        setElicitationResponses(defaults);
      }
    } catch (err) {
      console.error('Failed to fetch elicitation', err);
    }
  };

  const handleElicitationSubmit = async () => {
    if (!elicitation) return;
    try {
      await fetch('http://localhost:8000/api/elicitation/respond', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          request_id: elicitation.id,
          responses: elicitationResponses
        })
      });
      setElicitation(null);
      setElicitationResponses({});
    } catch (err) {
      console.error('Failed to submit elicitation', err);
    }
  };

  const uploadFile = async (file: File) => {
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

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) uploadFile(file);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    if (!isUploading && (pipelineState === 'IDLE' || pipelineState === 'COMPLETE')) {
      setIsDragging(true);
    }
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (isUploading || (pipelineState !== 'IDLE' && pipelineState !== 'COMPLETE')) return;
    
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      uploadFile(e.dataTransfer.files[0]);
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
      image:        { type: 'jpeg' as const, quality: 0.98 },
      html2canvas:  { scale: 2, useCORS: true, backgroundColor: '#1e1e24' },
      jsPDF:        { unit: 'mm', format: 'a4', orientation: 'portrait' }
    };
    
    html2pdf().set(opt).from(element).save();
  };

  const renderElicitationField = (field: any) => {
    const val = elicitationResponses[field.name];
    switch (field.field_type) {
      case 'text':
        return (
          <input
            type="text"
            value={val || ''}
            onChange={(e) => setElicitationResponses(prev => ({...prev, [field.name]: e.target.value}))}
          />
        );
      case 'textarea':
        return (
          <textarea
            value={val || ''}
            onChange={(e) => setElicitationResponses(prev => ({...prev, [field.name]: e.target.value}))}
          />
        );
      case 'select':
        return (
          <select
            value={val || ''}
            onChange={(e) => setElicitationResponses(prev => ({...prev, [field.name]: e.target.value}))}
          >
            <option value="">Select...</option>
            {field.options?.map((opt: string) => (
              <option key={opt} value={opt}>{opt}</option>
            ))}
          </select>
        );
      case 'radio':
        return (
          <div className="elicitation-radio-group">
            {field.options?.map((opt: string) => (
              <label key={opt} className="elicitation-radio-option">
                <input
                  type="radio"
                  name={field.name}
                  value={opt}
                  checked={val === opt}
                  onChange={(e) => setElicitationResponses(prev => ({...prev, [field.name]: e.target.value}))}
                />
                <span>{opt}</span>
              </label>
            ))}
          </div>
        );
      case 'checkbox':
        return (
          <label className="elicitation-checkbox-option">
            <input
              type="checkbox"
              checked={!!val}
              onChange={(e) => setElicitationResponses(prev => ({...prev, [field.name]: e.target.checked}))}
            />
            <span>{field.label}</span>
          </label>
        );
      case 'multi-select':
        return (
          <div className="elicitation-multi-select">
            {field.options?.map((opt: string) => (
              <label key={opt} className="elicitation-checkbox-option">
                <input
                  type="checkbox"
                  checked={(val || []).includes(opt)}
                  onChange={(e) => {
                    const current = val || [];
                    const updated = e.target.checked
                      ? [...current, opt]
                      : current.filter((v: string) => v !== opt);
                    setElicitationResponses(prev => ({...prev, [field.name]: updated}));
                  }}
                />
                <span>{opt}</span>
              </label>
            ))}
          </div>
        );
      default:
        return <input type="text" value={val || ''} onChange={(e) => setElicitationResponses(prev => ({...prev, [field.name]: e.target.value}))} />;
    }
  };

  return (
    <div className="app-container">
      {/* LEFT COLUMN: Controls & Pipeline */}
      <div className="flex flex-col gap-6">
        <h1 className="text-2xl font-bold mb-2">Agentic SOC Platform</h1>
        
        <div className="glass-panel">
          <h2 className="mb-4 text-lg">Input Telemetry</h2>
          <label 
            className={`upload-zone ${isUploading ? 'opacity-50' : ''} ${isDragging ? 'drag-active' : ''}`}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
          >
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
                  className={`pipeline-node ${isActive ? 'active' : ''} ${isCompleted ? 'completed' : ''} ${pipelineState === 'AWAITING_INPUT' && stage.id === 'AWAITING_INPUT' ? 'awaiting' : ''}`}
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
              <div className="btn-container">
                <button 
                  className={`btn ${reportView === 'ui' ? 'btn-primary' : 'btn-secondary'}`}
                  onClick={() => setReportView('ui')}
                >
                  Dashboard View
                </button>
                <button 
                  className={`btn ${reportView === 'markdown' ? 'btn-primary' : 'btn-secondary'}`}
                  onClick={() => setReportView('markdown')}
                >
                  Formal Report
                </button>
                {reportView === 'markdown' && (
                  <button 
                    className="btn btn-success"
                    onClick={handleDownloadPdf}
                  >
                    <Download className="w-4 h-4" />
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
                <div id="markdown-report-content" className="markdown-container prose">
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>{report.markdown_body}</ReactMarkdown>
                </div>
              ) : (
                <div className="flex-col gap-6">
                  <div className="report-cards">
                    <div className={`report-card ${report.risk_level.toLowerCase()}`}>
                      <div className="report-card-label">Overall Risk Level</div>
                      <div className="report-card-value">
                        {report.risk_level === 'CRITICAL' && <AlertTriangle className="text-red-500" />}
                        {report.risk_level}
                      </div>
                    </div>
                    <div className="report-card">
                      <div className="report-card-label">Generated At</div>
                      <div className="report-card-value" style={{ fontSize: '1.2rem' }}>
                        {new Date(report.generated_at).toLocaleString()}
                      </div>
                    </div>
                  </div>

                  <div className="report-section">
                    <h3 className="report-section-title">Executive Summary</h3>
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
                            formatter={(val: any) => [val === 4 ? 'Critical' : val === 3 ? 'High' : val === 2 ? 'Medium' : 'Low', 'Severity']}
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

                  <div className="report-section">
                    <h3 className="report-section-title">Detailed Findings ({report.findings?.length || 0})</h3>
                    <div className="flex-col gap-4">
                      {report.findings?.map((f: any, idx: number) => (
                        <div key={idx} className="p-4 border border-gray-800 rounded-lg bg-gray-900/20" style={{ marginBottom: '1rem' }}>
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
              </div>
              )}
            </div>
          )}
        </div>
      </div>
      
      {elicitation && (
        <div className="elicitation-overlay">
          <div className="elicitation-modal">
            <div className="elicitation-header">
              <div className="elicitation-agent-badge">
                {elicitation.agent} Agent
              </div>
              <h2>{elicitation.title}</h2>
              <p>{elicitation.description}</p>
            </div>

            {Object.keys(elicitation.context || {}).length > 0 && (
              <details className="elicitation-context" open>
                <summary>Evidence Context</summary>
                <pre>{JSON.stringify(elicitation.context, null, 2)}</pre>
              </details>
            )}

            <div className="elicitation-fields">
              {elicitation.fields?.map((field: any) => (
                <div key={field.name} className="elicitation-field">
                  <label>
                    {field.field_type !== 'checkbox' && field.label}
                    {field.required && <span className="required-star">*</span>}
                  </label>
                  {renderElicitationField(field)}
                </div>
              ))}
            </div>

            <div className="elicitation-actions">
              <div className={`elicitation-timer ${elicitationTimer < 60 ? 'warning' : ''}`}>
                <Clock className="w-4 h-4" />
                {Math.floor(elicitationTimer / 60)}:{String(elicitationTimer % 60).padStart(2, '0')} remaining
              </div>
              <button className="btn btn-primary" onClick={handleElicitationSubmit}>
                Submit Response
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
    
  );
}
