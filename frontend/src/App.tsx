import { useState, useEffect, useRef, useCallback, startTransition } from "react";
import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";
import { Shield, Scan, AlertTriangle, CheckCircle2, FileWarning, Trash2, RefreshCw, Lock, Activity, Cpu, HardDrive, Upload, FlaskConical, Download, Wifi, WifiOff } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/confirm-dialog";
import { cn, getApiErrorMessage, WS_URL } from "@/lib/utils";
import { api } from "@/lib/api";

interface Threat {
  id: string;
  file_id: string;
  name: string;
  type: string;
  severity: "critical" | "high" | "medium" | "low";
  status: "detected" | "quarantined" | "cleaned";
  confidence: number;
  yara_matches?: string[] | null;
  sandbox_behavior?: string[] | null;
}

interface ScanResult {
  filesScanned: number;
  threatsFound: number;
  duration: string;
  status: "idle" | "scanning" | "complete";
  progress: number;
}

interface Toast {
  message: string;
  type: "success" | "error";
}

interface BatchResult {
  successCount: number;
  failureCount: number;
  failures: Array<{ id: string; error: string }>;
}

const severityColors: Record<string, string> = {
  critical: "bg-red-100 text-red-700 border-red-200",
  high: "bg-orange-100 text-orange-700 border-orange-200",
  medium: "bg-yellow-100 text-yellow-700 border-yellow-200",
  low: "bg-blue-100 text-blue-700 border-blue-200",
};

const statusColors: Record<string, string> = {
  detected: "bg-red-100 text-red-700",
  quarantined: "bg-yellow-100 text-yellow-700",
  cleaned: "bg-green-100 text-green-700",
};

const MAX_FILE_SIZE = 50 * 1024 * 1024;
const ALLOWED_EXTENSIONS = new Set([
  ".exe", ".dll", ".pdf", ".docx", ".zip", ".txt", ".ps1",
  ".doc", ".xls", ".xlsx", ".ppt", ".pptx", ".js", ".py",
  ".sh", ".bat", ".cmd", ".msi", ".apk", ".ipa", ".rar", ".7z",
]);
const DANGEROUS_EXTENSIONS = new Set([
  ".exe", ".dll", ".bat", ".cmd", ".ps1", ".js", ".vbs",
  ".wsf", ".scr", ".pif", ".com", ".msi", ".hta", ".cpl", ".jar",
]);

function validateFile(file: File): string | null {
  if (file.size > MAX_FILE_SIZE) {
    return `文件大小超出限制 (最大 50MB，当前 ${(file.size / 1024 / 1024).toFixed(1)}MB)`;
  }

  const ext = "." + file.name.split(".").pop()?.toLowerCase();
  if (!ALLOWED_EXTENSIONS.has(ext)) {
    return `不支持的文件类型: ${ext || "未知"}`;
  }

  const parts = file.name.split(".");
  if (parts.length > 2) {
    const finalExt = "." + parts.pop()?.toLowerCase();
    if (DANGEROUS_EXTENSIONS.has(finalExt)) {
      return "DOUBLE_EXTENSION_WARNING";
    }
  }

  return null;
}

async function runBatch<T>(
  items: T[],
  concurrency = 5,
  worker: (item: T, signal: AbortSignal) => Promise<{ id: string; result: unknown }>,
  signal?: AbortSignal
): Promise<BatchResult> {
  const results: Array<{ id: string; result: unknown }> = [];
  let failureCount = 0;
  const failures: Array<{ id: string; error: string }> = [];

  for (let i = 0; i < items.length; i += concurrency) {
    if (signal?.aborted) break;
    const chunk = items.slice(i, i + concurrency);
    const settled = await Promise.allSettled(chunk.map((item) => worker(item, signal!)));

    for (const outcome of settled) {
      if (outcome.status === "fulfilled") {
        results.push(outcome.value);
      } else {
        failureCount++;
        const errorMessage = getApiErrorMessage(outcome.reason);
        failures.push({ id: "unknown", error: errorMessage });
      }
    }
  }

  return { successCount: results.length, failureCount, failures: failures.slice(0, 3) };
}

type WsStatus = "connecting" | "connected" | "disconnected" | "reconnecting";

export default function App() {
  const [threats, setThreats] = useState<Threat[]>([]);
  const [threatsTotal, setThreatsTotal] = useState(0);
  const [scanResult, setScanResult] = useState<ScanResult>({
    filesScanned: 0,
    threatsFound: 0,
    duration: "0:00",
    status: "idle",
    progress: 0,
  });
  const [realTimeProtection, setRealTimeProtection] = useState(true);
  const [autoQuarantine, setAutoQuarantine] = useState(true);
  const [toast, setToast] = useState<Toast | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [quarantineDialogOpen, setQuarantineDialogOpen] = useState(false);
  const [cleanDialogOpen, setCleanDialogOpen] = useState(false);
  const [pendingBatchType, setPendingBatchType] = useState<"quarantine" | "clean" | null>(null);
  const [doubleExtDialogOpen, setDoubleExtDialogOpen] = useState(false);
  const [pendingFile, setPendingFile] = useState<File | null>(null);

  const [quarantineTab, setQuarantineTab] = useState<"all" | "quarantined">("all");
  const [detailDialogOpen, setDetailDialogOpen] = useState(false);
  const [selectedThreat, setSelectedThreat] = useState<Threat | null>(null);
  const [reportLoading, setReportLoading] = useState(false);
  const [wsStatus, setWsStatus] = useState<WsStatus>("disconnected");

  const realTimeProtectionRef = useRef(realTimeProtection);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectAttemptsRef = useRef(0);
  const reconnectTimerRef = useRef<number | null>(null);
  const lastAlertTimeRef = useRef<Map<string, number>>(new Map());
  const batchAbortControllerRef = useRef<AbortController | null>(null);
  const wsUrlRef = useRef(WS_URL);
  const wsTokenRef = useRef("");
  const heartbeatTimerRef = useRef<number | null>(null);
  const wsStatusRef = useRef<WsStatus>("disconnected");

  useEffect(() => {
    realTimeProtectionRef.current = realTimeProtection;
  }, [realTimeProtection]);

  useEffect(() => {
    wsTokenRef.current = typeof window !== "undefined" ? localStorage.getItem("access_token") || "" : "";
  }, []);

  useEffect(() => {
    wsStatusRef.current = wsStatus;
  }, [wsStatus]);

  const updateWsStatus = useCallback((status: WsStatus) => {
    wsStatusRef.current = status;
    setWsStatus(status);
  }, []);

  const fetchThreats = useCallback(async () => {
    try {
      const res = await api.getThreats({ limit: 100, offset: 0 });
      const data = res.data;
      startTransition(() => {
        setThreats(data.items as Threat[]);
        setThreatsTotal(data.total);
      });
    } catch (err) {
      console.error("Failed to fetch threats:", err);
      startTransition(() => {
        setToast({ message: "⚠️ 无法连接后端服务", type: "error" });
      });
    }
  }, []);

  useEffect(() => {
    if (toast) {
      const timer = setTimeout(() => setToast(null), 3000);
      return () => clearTimeout(timer);
    }
  }, [toast]);

  useEffect(() => {
    fetchThreats();
  }, [fetchThreats]);

  useEffect(() => {
    let ws: WebSocket | null = null;
    let isMounted = true;
    let heartbeatInterval: number | null = null;

    const startHeartbeat = () => {
      if (heartbeatInterval) {
        window.clearInterval(heartbeatInterval);
      }
      heartbeatInterval = window.setInterval(() => {
        if (ws && ws.readyState === WebSocket.OPEN) {
          try {
            ws.send("ping");
          } catch {
            // ignore
          }
        }
      }, 30000);
    };

    const stopHeartbeat = () => {
      if (heartbeatInterval) {
        window.clearInterval(heartbeatInterval);
        heartbeatInterval = null;
      }
    };

    const connect = () => {
      try {
        const token = wsTokenRef.current;
        const url = `${wsUrlRef.current}/ws/monitor?token=${encodeURIComponent(token)}`;
        ws = new WebSocket(url);
        wsRef.current = ws;

        if (!isMounted) return;

        updateWsStatus("connecting");

        ws.onopen = () => {
          if (!isMounted) return;
          reconnectAttemptsRef.current = 0;
          updateWsStatus("connected");
          startHeartbeat();
          startTransition(() => {
            setToast({ message: "实时防护连接已建立", type: "success" });
          });
        };

        ws.onmessage = (event) => {
          if (!isMounted) return;
          try {
            const data = JSON.parse(event.data);
            if (data === "pong") {
              return;
            }

            if (data.type === "scan_complete") {
              const threatId = data.threat_id;
              if (threatId) {
                setThreats((prev) => {
                  const exists = prev.some((t) => t.id === threatId || t.file_id === threatId);
                  if (!exists) {
                    const newThreat: Threat = {
                      id: threatId,
                      file_id: threatId,
                      name: data.file_name || "Unknown",
                      type: data.threat_type || "Unknown",
                      severity: data.severity || "high",
                      status: "detected",
                      confidence: data.confidence || 0,
                    };
                    return [newThreat, ...prev];
                  }
                  return prev;
                });
                setThreatsTotal((prev) => prev + 1);
              }
              return;
            }

            if (!data.is_threat) return;

            if (!realTimeProtectionRef.current) {
              console.log("[WS] 实时防护已关闭，丢弃威胁事件:", data);
              return;
            }

            const now = Date.now();
            const lastAlert = lastAlertTimeRef.current.get(data.behavior_type);
            if (lastAlert && now - lastAlert < 5000) {
              console.log("[WS] 静默期，跳过重复告警:", data.behavior_type);
              return;
            }
            lastAlertTimeRef.current.set(data.behavior_type, now);

            const newThreat: Threat = {
              id: `ws-${data.event_id}`,
              file_id: data.event_id,
              name: data.process_name,
              type: data.behavior_type,
              severity: data.risk_score >= 90 ? "critical" : "high",
              status: "detected",
              confidence: data.risk_score,
            };

            setThreats((prev) => [newThreat, ...prev]);
            setThreatsTotal((prev) => prev + 1);

            startTransition(() => {
              setToast({
                message: `🛡️ 实时防护已拦截: ${data.behavior_type} - ${data.process_name}`,
                type: "error",
              });
            });

            api.quarantine(newThreat.id)
              .then(() => {
                setThreats((prev) =>
                  prev.map((t) =>
                    t.id === newThreat.id ? { ...t, status: "quarantined" } : t
                  )
                );
              })
              .catch((err) => {
                console.error("自动隔离失败:", err);
                startTransition(() => {
                  setToast({
                    message: `自动隔离失败: ${getApiErrorMessage(err)}`,
                    type: "error",
                  });
                });
              });
          } catch (err) {
            console.error("处理 WebSocket 消息失败:", err);
          }
        };

        ws.onclose = () => {
          if (!isMounted) return;
          stopHeartbeat();
          updateWsStatus("disconnected");
          startTransition(() => {
            setToast({ message: "实时防护连接断开，正在重连...", type: "error" });
          });
          const delay = Math.min(2000 * Math.pow(2, reconnectAttemptsRef.current), 8000);
          updateWsStatus("reconnecting");
          const timer = window.setTimeout(() => {
            reconnectAttemptsRef.current += 1;
            connect();
          }, delay);
          reconnectTimerRef.current = timer;
        };

        ws.onerror = () => {
          if (!isMounted) return;
          updateWsStatus("disconnected");
          ws?.close();
        };
      } catch (err) {
        console.error("WebSocket 连接失败:", err);
        if (isMounted) {
          updateWsStatus("disconnected");
        }
      }
    };

    connect();

    return () => {
      isMounted = false;
      stopHeartbeat();
      if (batchAbortControllerRef.current) {
        batchAbortControllerRef.current.abort();
      }
      if (reconnectTimerRef.current) {
        window.clearTimeout(reconnectTimerRef.current);
      }
      if (ws) {
        ws.onclose = null;
        ws.onerror = null;
        ws.onmessage = null;
        ws.onopen = null;
        ws.close();
      }
      wsRef.current = null;
    };
  }, [updateWsStatus]);

  const handleScanClick = () => {
    fileInputRef.current?.click();
  };

  const performScan = async (file: File) => {
    setScanResult({ filesScanned: 0, threatsFound: 0, duration: "0:00", status: "scanning", progress: 0 });
    try {
      let progress = 0;
      const progressInterval = setInterval(() => {
        progress += 15;
        if (progress <= 90) {
          setScanResult((prev) => ({ ...prev, progress, filesScanned: Math.floor(progress * 128) }));
        }
      }, 200);

      const data = await api.scanUpload(file, (p) => {
        progress = p;
        setScanResult((prev) => ({ ...prev, progress, filesScanned: Math.floor(p * 128) }));
      });

      clearInterval(progressInterval);
      setScanResult({
        filesScanned: 1,
        threatsFound: data.status === "threat_detected" ? 1 : 0,
        duration: "0:01",
        status: "complete",
        progress: 100,
      });

      if (data.status === "threat_detected" && data.threat) {
        const threat = data.threat as { id: string; name: string; confidence: number };
        setToast({ message: `🚨 发现威胁: ${threat.name} (置信度: ${threat.confidence}%)`, type: "error" });
        if (autoQuarantine) {
          await quarantineThreat(threat.id);
        } else {
          fetchThreats();
        }
      } else {
        setToast({ message: "✅ 文件安全，AI 未检测到威胁", type: "success" });
      }
    } catch (err) {
      setScanResult((prev) => ({ ...prev, status: "idle", progress: 0 }));
      setToast({ message: `❌ 扫描失败: ${getApiErrorMessage(err)}`, type: "error" });
    }
  };

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    const validationResult = validateFile(file);
    if (validationResult === "DOUBLE_EXTENSION_WARNING") {
      setPendingFile(file);
      setDoubleExtDialogOpen(true);
      event.target.value = "";
      return;
    } else if (validationResult) {
      setToast({ message: validationResult, type: "error" });
      event.target.value = "";
      return;
    }

    await performScan(file);
    event.target.value = "";
  };

  const confirmDoubleExtScan = async () => {
    if (!pendingFile) return;
    setDoubleExtDialogOpen(false);
    await performScan(pendingFile);
    setPendingFile(null);
  };

  const quarantineThreat = async (id: string) => {
    try {
      await api.quarantine(id);
      setToast({ message: "威胁已成功隔离", type: "success" });
      fetchThreats();
    } catch (err) {
      setToast({ message: `隔离操作失败: ${getApiErrorMessage(err)}`, type: "error" });
    }
  };

  const cleanThreat = async (id: string) => {
    try {
      await api.clean(id);
      setToast({ message: "威胁已成功清除", type: "success" });
      fetchThreats();
    } catch (err) {
      setToast({ message: `清除操作失败: ${getApiErrorMessage(err)}`, type: "error" });
    }
  };

  const restoreThreat = async (id: string) => {
    try {
      await api.restore(id);
      setToast({ message: "威胁已成功恢复", type: "success" });
      fetchThreats();
    } catch (err) {
      setToast({ message: `恢复操作失败: ${getApiErrorMessage(err)}`, type: "error" });
    }
  };

  const permanentlyDeleteThreat = async (id: string) => {
    try {
      await api.permanentlyDelete(id);
      setToast({ message: "威胁已永久删除", type: "success" });
      fetchThreats();
    } catch (err) {
      setToast({ message: `删除操作失败: ${getApiErrorMessage(err)}`, type: "error" });
    }
  };

  const quarantineAll = async () => {
    const detected = threats.filter((t) => t.status === "detected");
    if (detected.length === 0) return;

    if (batchAbortControllerRef.current) {
      batchAbortControllerRef.current.abort();
    }

    setPendingBatchType("quarantine");
    setQuarantineDialogOpen(true);
  };

  const cleanAll = async () => {
    const detected = threats.filter((t) => t.status === "detected");
    if (detected.length === 0) return;

    if (batchAbortControllerRef.current) {
      batchAbortControllerRef.current.abort();
    }

    setPendingBatchType("clean");
    setCleanDialogOpen(true);
  };

  const executeBatch = async () => {
    const type = pendingBatchType;
    if (!type) return;

    const detected = threats.filter((t) => t.status === "detected");
    if (detected.length === 0) return;

    if (batchAbortControllerRef.current) {
      batchAbortControllerRef.current.abort();
    }
    const controller = new AbortController();
    batchAbortControllerRef.current = controller;

    try {
      const worker = type === "quarantine"
        ? (t: Threat, s: AbortSignal) => api.quarantine(t.id, s).then(() => ({ id: t.id, result: "ok" }))
        : (t: Threat, s: AbortSignal) => api.clean(t.id, s).then(() => ({ id: t.id, result: "ok" }));

      const result = await runBatch(detected, 5, worker, controller.signal);
      setQuarantineDialogOpen(false);
      setCleanDialogOpen(false);
      setPendingBatchType(null);
      fetchThreats();

      if (result.failureCount > 0) {
        const failureMessages = result.failures.map((f) => `${f.id}: ${f.error}`).join("\n");
        setToast({
          message: `批量操作完成，成功 ${result.successCount} 个，失败 ${result.failureCount} 个。\n${failureMessages}`,
          type: "error",
        });
      } else {
        setToast({ message: `批量操作成功，已完成 ${result.successCount} 个威胁`, type: "success" });
      }
    } catch (err) {
      if (err instanceof Error && err.name === "AbortError") {
        console.log("Batch operation aborted");
        return;
      }
      setToast({ message: `批量操作失败: ${getApiErrorMessage(err)}`, type: "error" });
    } finally {
      batchAbortControllerRef.current = null;
    }
  };

  const openThreatDetail = (threat: Threat) => {
    setSelectedThreat(threat);
    setDetailDialogOpen(true);
  };

  const exportPdf = async () => {
    setReportLoading(true);
    try {
      const res = await api.exportReport();
      const report = res.data;
      const doc = new jsPDF();
      const now = new Date(report.generated_at);

      doc.setFontSize(18);
      doc.text("AI Shield Pro - Security Audit Report", 14, 22);
      doc.setFontSize(10);
      doc.text(`Generated: ${now.toLocaleString()}`, 14, 30);

      doc.setFontSize(14);
      doc.text("Executive Summary", 14, 42);
      doc.setFontSize(10);
      doc.text(`Total Threats: ${report.summary.total}`, 14, 50);
      doc.text(`By Severity: ${JSON.stringify(report.summary.by_severity)}`, 14, 56);
      doc.text(`By Type: ${JSON.stringify(report.summary.by_type)}`, 14, 62);

      const tableColumn = ["File ID", "Name", "Type", "Severity", "Confidence", "Status"];
      const tableRows: string[][] = [];

      for (const threat of report.threats) {
        const row = [
          threat.file_id,
          threat.name,
          threat.type,
          threat.severity,
          `${threat.confidence}%`,
          threat.status,
        ];
        tableRows.push(row);
      }

      autoTable(doc, {
        head: [tableColumn],
        body: tableRows,
        startY: 70,
        theme: "grid",
        headStyles: { fillColor: [6, 78, 59] },
      });

      doc.save("AI_Shield_Security_Report.pdf");
      setToast({ message: "PDF 审计报告已导出", type: "success" });
    } catch (err) {
      setToast({ message: `导出报告失败: ${getApiErrorMessage(err)}`, type: "error" });
    } finally {
      setReportLoading(false);
    }
  };

  const detectedCount = threats.filter((t) => t.status === "detected").length;
  const quarantinedCount = threats.filter((t) => t.status === "quarantined").length;
  const cleanedCount = threats.filter((t) => t.status === "cleaned").length;

  const displayedThreats = quarantineTab === "quarantined"
    ? threats.filter((t) => t.status === "quarantined")
    : threats;

  const wsStatusLabel: Record<WsStatus, string> = {
    connecting: "连接中...",
    connected: "已连接",
    disconnected: "已断开",
    reconnecting: "重连中...",
  };

  const wsStatusColor: Record<WsStatus, string> = {
    connecting: "text-yellow-600",
    connected: "text-emerald-600",
    disconnected: "text-red-600",
    reconnecting: "text-yellow-600",
  };

  return (
    <div className="min-h-screen bg-slate-100 relative">
      {toast && (
        <div
          className={`fixed top-6 right-6 z-50 px-4 py-3 rounded-lg shadow-lg border flex items-center gap-3 animate-in slide-in-from-top-5 fade-in duration-300 ${
            toast.type === "success" ? "bg-emerald-50 border-emerald-200 text-emerald-800" : "bg-red-50 border-red-200 text-red-800"
          }`}
        >
          {toast.type === "success" ? <CheckCircle2 className="w-5 h-5" /> : <AlertTriangle className="w-5 h-5" />}
          <span className="font-medium text-sm whitespace-pre-line">{toast.message}</span>
        </div>
      )}

      <input type="file" ref={fileInputRef} className="hidden" onChange={handleFileUpload} />

      <header className="bg-slate-900 text-white border-b border-slate-800">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-emerald-500 flex items-center justify-center">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="text-xl font-bold font-serif">AI Shield Pro</h1>
              <p className="text-xs text-slate-400">智能威胁检测系统</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2 text-sm">
              {wsStatus === "connected" ? (
                <Wifi className="w-4 h-4 text-emerald-400" />
              ) : (
                <WifiOff className="w-4 h-4 text-slate-400" />
              )}
              <span className={cn("text-xs", wsStatusColor[wsStatus])}>
                {wsStatusLabel[wsStatus]}
              </span>
            </div>
            <div className="flex items-center gap-2 text-sm">
              <span className={cn("w-2 h-2 rounded-full", realTimeProtection ? "bg-emerald-400 animate-pulse" : "bg-slate-600")} />
              <span className="text-slate-300">实时防护</span>
            </div>
            <Badge className="bg-emerald-500/20 text-emerald-300 border-emerald-500/30">AI 引擎已激活</Badge>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-8">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
          <Card className="bg-white border-slate-200 shadow-sm">
            <CardContent className="p-5">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-slate-500">已扫描文件</p>
                  <p className="text-2xl font-bold text-slate-900 mt-1">{scanResult.filesScanned.toLocaleString()}</p>
                </div>
                <div className="w-10 h-10 rounded-lg bg-blue-100 flex items-center justify-center">
                  <HardDrive className="w-5 h-5 text-blue-600" />
                </div>
              </div>
            </CardContent>
          </Card>
          <Card className="bg-white border-slate-200 shadow-sm">
            <CardContent className="p-5">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-slate-500">检测到威胁</p>
                  <p className="text-2xl font-bold text-red-600 mt-1">{detectedCount}</p>
                </div>
                <div className="w-10 h-10 rounded-lg bg-red-100 flex items-center justify-center">
                  <AlertTriangle className="w-5 h-5 text-red-600" />
                </div>
              </div>
            </CardContent>
          </Card>
          <Card className="bg-white border-slate-200 shadow-sm">
            <CardContent className="p-5">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-slate-500">已隔离</p>
                  <p className="text-2xl font-bold text-yellow-600 mt-1">{quarantinedCount}</p>
                </div>
                <div className="w-10 h-10 rounded-lg bg-yellow-100 flex items-center justify-center">
                  <Lock className="w-5 h-5 text-yellow-600" />
                </div>
              </div>
            </CardContent>
          </Card>
          <Card className="bg-white border-slate-200 shadow-sm">
            <CardContent className="p-5">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-slate-500">已清除</p>
                  <p className="text-2xl font-bold text-emerald-600 mt-1">{cleanedCount}</p>
                </div>
                <div className="w-10 h-10 rounded-lg bg-emerald-100 flex items-center justify-center">
                  <CheckCircle2 className="w-5 h-5 text-emerald-600" />
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-1 space-y-6">
            <Card className="bg-white border-slate-200 shadow-sm">
              <CardHeader className="border-b border-slate-100">
                <CardTitle className="text-lg font-semibold flex items-center gap-2">
                  <Scan className="w-5 h-5 text-emerald-600" />
                  AI 文件扫描
                </CardTitle>
              </CardHeader>
              <CardContent className="p-6">
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-slate-600">扫描进度</span>
                    <span className="text-sm font-medium text-slate-900">
                      {scanResult.status === "scanning" ? `${Math.floor(scanResult.progress)}%` : "就绪"}
                    </span>
                  </div>
                  <Progress value={scanResult.progress} className="h-2 bg-slate-100" />
                  {scanResult.status === "scanning" && (
                    <div className="flex items-center gap-2 text-sm text-slate-500">
                      <Activity className="w-4 h-4 animate-pulse text-emerald-600" />
                       正在提取 PE 特征并进行 AI 推理...
                    </div>
                  )}
                  {scanResult.status === "complete" && (
                    <div className="flex items-center gap-2 text-sm text-emerald-600">
                      <CheckCircle2 className="w-4 h-4" />
                       扫描完成，用时 {scanResult.duration}
                    </div>
                  )}
                  <Button onClick={handleScanClick} disabled={scanResult.status === "scanning"} className="w-full bg-emerald-600 hover:bg-emerald-700 text-white">
                    {scanResult.status === "scanning" ? (
                      <><RefreshCw className="w-4 h-4 mr-2 animate-spin" /> 分析中...</>
                    ) : (
                      <><Upload className="w-4 h-4 mr-2" /> 选择文件扫描</>
                    )}
                  </Button>
                </div>
              </CardContent>
            </Card>

            <Card className="bg-white border-slate-200 shadow-sm">
              <CardHeader className="border-b border-slate-100">
                <CardTitle className="text-lg font-semibold flex items-center gap-2">
                  <Cpu className="w-5 h-5 text-indigo-600" />
                  AI 防护设置
                </CardTitle>
              </CardHeader>
              <CardContent className="p-6 space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <Label className="text-sm font-medium text-slate-900">实时防护</Label>
                    <p className="text-xs text-slate-500 mt-1">实时监控文件行为</p>
                  </div>
                  <Switch checked={realTimeProtection} onCheckedChange={setRealTimeProtection} className="data-[state=checked]:bg-emerald-600" />
                </div>
                <div className="flex items-center justify-between">
                  <div>
                    <Label className="text-sm font-medium text-slate-900">自动隔离</Label>
                    <p className="text-xs text-slate-500 mt-1">检测到威胁时自动隔离</p>
                  </div>
                  <Switch checked={autoQuarantine} onCheckedChange={setAutoQuarantine} className="data-[state=checked]:bg-emerald-600" />
                </div>
              </CardContent>
            </Card>

            <Card className="bg-white border-slate-200 shadow-sm">
              <CardHeader className="border-b border-slate-100">
                <CardTitle className="text-lg font-semibold flex items-center gap-2">
                  <FlaskConical className="w-5 h-5 text-purple-600" />
                  审计与报告
                </CardTitle>
              </CardHeader>
              <CardContent className="p-6">
                <Button onClick={exportPdf} disabled={reportLoading || threats.length === 0} className="w-full bg-slate-900 hover:bg-slate-800 text-white">
                  {reportLoading ? (
                    <><RefreshCw className="w-4 h-4 mr-2 animate-spin" /> 生成中...</>
                  ) : (
                    <><Download className="w-4 h-4 mr-2" /> 导出 PDF 审计报告</>
                  )}
                </Button>
                <p className="text-xs text-slate-500 mt-2">包含威胁统计摘要与详细列表</p>
              </CardContent>
            </Card>
          </div>

          <div className="lg:col-span-2">
            <Card className="bg-white border-slate-200 shadow-sm">
              <CardHeader className="border-b border-slate-100 flex flex-row items-center justify-between">
                <div className="flex items-center gap-4">
                  <CardTitle className="text-lg font-semibold flex items-center gap-2">
                    <FileWarning className="w-5 h-5 text-red-600" />
                    威胁管理中心
                  </CardTitle>
                  <div className="flex rounded-lg border border-slate-200 overflow-hidden">
                    <button
                      onClick={() => setQuarantineTab("all")}
                      className={`px-3 py-1 text-xs font-medium transition-colors ${quarantineTab === "all" ? "bg-slate-900 text-white" : "bg-white text-slate-600 hover:bg-slate-50"}`}
                    >
                      全部 ({threatsTotal})
                    </button>
                    <button
                      onClick={() => setQuarantineTab("quarantined")}
                      className={`px-3 py-1 text-xs font-medium transition-colors ${quarantineTab === "quarantined" ? "bg-slate-900 text-white" : "bg-white text-slate-600 hover:bg-slate-50"}`}
                    >
                      隔离区 ({quarantinedCount})
                    </button>
                  </div>
                </div>
                <div className="flex gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={quarantineAll}
                    disabled={detectedCount === 0}
                    className="text-yellow-600 border-yellow-200 hover:bg-yellow-50"
                  >
                    <Lock className="w-4 h-4 mr-1" /> 全部隔离
                  </Button>
                  <Button
                    size="sm"
                    onClick={cleanAll}
                    disabled={detectedCount === 0}
                    className="bg-emerald-600 hover:bg-emerald-700 text-white"
                  >
                    <Trash2 className="w-4 h-4 mr-1" /> 全部清除
                  </Button>
                </div>
              </CardHeader>
              <CardContent className="p-0">
                {displayedThreats.length === 0 ? (
                  <div className="p-12 text-center">
                    <CheckCircle2 className="w-12 h-12 text-emerald-500 mx-auto mb-4" />
                    <p className="text-lg font-medium text-slate-900">
                      {quarantineTab === "quarantined" ? "隔离区为空" : "系统安全"}
                    </p>
                    <p className="text-sm text-slate-500 mt-1">
                      {quarantineTab === "quarantined" ? "暂无已隔离的威胁" : "暂无检测记录或所有威胁已处理"}
                    </p>
                  </div>
                ) : (
                  <div className="divide-y divide-slate-100 max-h-[600px] overflow-y-auto">
                    {displayedThreats.map((threat) => (
                      <div key={threat.id} className="p-4 hover:bg-slate-50 transition-colors">
                        <div className="flex items-start justify-between gap-4">
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="font-medium text-slate-900">{threat.name}</span>
                              <Badge className={cn("border", severityColors[threat.severity])}>
                                {threat.severity === "critical" ? "严重" : threat.severity === "high" ? "高危" : threat.severity === "medium" ? "中等" : "低危"}
                              </Badge>
                              <Badge className={cn("border", statusColors[threat.status])}>
                                {threat.status === "detected" ? "已检测" : threat.status === "quarantined" ? "已隔离" : "已清除"}
                              </Badge>
                            </div>
                            <p className="text-sm text-slate-500 mt-1 font-mono text-xs">{threat.file_id}</p>
                            <div className="flex items-center gap-2 mt-2">
                              <span className="text-xs text-slate-400">类型: {threat.type}</span>
                              <span className="text-xs text-slate-400">|</span>
                              <span className="text-xs text-slate-400">AI 置信度: {threat.confidence}%</span>
                            </div>
                          </div>
                          <div className="flex gap-2 shrink-0">
                            <Button variant="outline" size="sm" onClick={() => openThreatDetail(threat)} className="text-slate-600 border-slate-200 hover:bg-slate-50">
                              <FlaskConical className="w-3 h-3 mr-1" /> 详情
                            </Button>
                            {threat.status === "detected" && (
                              <>
                                <Button variant="outline" size="sm" onClick={() => quarantineThreat(threat.id)} className="text-yellow-600 border-yellow-200 hover:bg-yellow-50">
                                  <Lock className="w-3 h-3 mr-1" /> 隔离
                                </Button>
                                <Button size="sm" onClick={() => cleanThreat(threat.id)} className="bg-emerald-600 hover:bg-emerald-700 text-white">
                                  <Trash2 className="w-3 h-3 mr-1" /> 清除
                                </Button>
                              </>
                            )}
                            {threat.status === "quarantined" && (
                              <>
                                <Button variant="outline" size="sm" onClick={() => restoreThreat(threat.id)} className="text-blue-600 border-blue-200 hover:bg-blue-50">
                                  <RefreshCw className="w-3 h-3 mr-1" /> 恢复
                                </Button>
                                <Button size="sm" onClick={() => permanentlyDeleteThreat(threat.id)} className="bg-red-600 hover:bg-red-700 text-white">
                                  <Trash2 className="w-3 h-3 mr-1" /> 永久删除
                                </Button>
                              </>
                            )}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </div>
      </main>

      <Dialog open={quarantineDialogOpen} onOpenChange={setQuarantineDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>确认批量隔离</DialogTitle>
            <DialogDescription>
              此操作将对 {threats.filter((t) => t.status === "detected").length} 个已检测威胁执行隔离。该过程采用分批并发（每批 5 个）执行，以提高稳定性并减少阻塞。
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setQuarantineDialogOpen(false)}>取消</Button>
            <Button onClick={executeBatch} className="bg-yellow-600 hover:bg-yellow-700 text-white">
              确认隔离
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={cleanDialogOpen} onOpenChange={setCleanDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>确认批量清除</DialogTitle>
            <DialogDescription>
              此操作将对 {threats.filter((t) => t.status === "detected").length} 个已检测威胁执行清除。该过程采用分批并发（每批 5 个）执行，以提高稳定性并减少阻塞。
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCleanDialogOpen(false)}>取消</Button>
            <Button onClick={executeBatch} className="bg-emerald-600 hover:bg-emerald-700 text-white">
              确认清除
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={doubleExtDialogOpen} onOpenChange={setDoubleExtDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>文件扩展名风险警告</DialogTitle>
            <DialogDescription>
              文件 "{pendingFile?.name}" 包含多个扩展名，最终后缀为高危可执行文件类型。这可能是伪装的可执行文件。是否仍要继续上传交由后端深度判定？
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => { setDoubleExtDialogOpen(false); setPendingFile(null); }}>取消</Button>
            <Button onClick={confirmDoubleExtScan} className="bg-yellow-600 hover:bg-yellow-700 text-white">
              仍要上传
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={detailDialogOpen} onOpenChange={setDetailDialogOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>沙箱行为分析 - {selectedThreat?.name}</DialogTitle>
            <DialogDescription>
              YARA 规则命中与微虚拟机 API 调用序列
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <h4 className="text-sm font-semibold text-slate-900 mb-2">YARA 规则命中</h4>
              <div className="flex flex-wrap gap-2">
                {selectedThreat?.yara_matches?.length ? (
                  selectedThreat.yara_matches.map((rule) => (
                    <Badge key={rule} className="bg-red-50 text-red-700 border-red-200">{rule}</Badge>
                  ))
                ) : (
                  <span className="text-sm text-slate-500">无 YARA 命中</span>
                )}
              </div>
            </div>
            <div>
              <h4 className="text-sm font-semibold text-slate-900 mb-2">沙箱 API 调用链</h4>
              <div className="bg-slate-900 rounded-lg p-4 overflow-x-auto">
                <code className="text-xs text-emerald-400 font-mono">
                  {selectedThreat?.sandbox_behavior?.length ? (
                    selectedThreat.sandbox_behavior.join(" -> ")
                  ) : (
                    <span className="text-slate-500">无沙箱行为数据</span>
                  )}
                </code>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <span className="text-slate-500">严重程度:</span>
                <span className="ml-2 font-medium">{selectedThreat?.severity}</span>
              </div>
              <div>
                <span className="text-slate-500">置信度:</span>
                <span className="ml-2 font-medium">{selectedThreat?.confidence}%</span>
              </div>
              <div>
                <span className="text-slate-500">状态:</span>
                <span className="ml-2 font-medium">{selectedThreat?.status}</span>
              </div>
              <div>
                <span className="text-slate-500">类型:</span>
                <span className="ml-2 font-medium">{selectedThreat?.type}</span>
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDetailDialogOpen(false)}>关闭</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
