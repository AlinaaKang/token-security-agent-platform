import {
  CircleAlert,
  ClipboardCheck,
  Eye,
  FileDown,
  LoaderCircle,
  Play,
  ShieldCheck,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { api } from "../api";
import type {
  Decision,
  LabRunResult,
  LabToolExecution,
  LabToolId,
  LabToolResult,
} from "../types";


const decisionLabels: Record<Decision, string> = {
  allow: "放行",
  review: "人工复核",
  block: "拦截",
  sanitize_recheck: "净化后复检",
};

const toolIcons = {
  gateway_enforcement: ShieldCheck,
  security_case: ClipboardCheck,
  evidence_bundle: FileDown,
} as const;

function mergeExecutions(
  primary: LabToolExecution[],
  secondary: LabToolExecution[],
): LabToolExecution[] {
  const byId = new Map<string, LabToolExecution>();
  for (const item of [...primary, ...secondary]) {
    if (!byId.has(item.execution_id)) byId.set(item.execution_id, item);
  }
  return [...byId.values()];
}

function formatTimestamp(value: string): string {
  const parts = new Intl.DateTimeFormat("zh-CN", {
    timeZone: "Asia/Shanghai",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
  }).formatToParts(new Date(value));
  const part = (type: Intl.DateTimeFormatPartTypes) =>
    parts.find((item) => item.type === type)?.value ?? "--";
  return `${part("year")}/${part("month")}/${part("day")} ${part("hour")}:${part("minute")}:${part("second")}`;
}

interface LabToolCenterProps {
  run: LabRunResult;
  hidden?: boolean;
}

export function LabToolCenter({ run, hidden = false }: LabToolCenterProps) {
  const [history, setHistory] = useState<LabToolExecution[]>([]);
  const [previewResults, setPreviewResults] = useState<Map<LabToolId, LabToolResult>>(
    () => new Map(),
  );
  const [busy, setBusy] = useState<{ toolId: LabToolId; kind: "preview" | "execute" } | null>(null);
  const [confirmation, setConfirmation] = useState<LabToolId | null>(null);
  const [error, setError] = useState<string | null>(null);
  const retryKeys = useRef(new Map<LabToolId, string>());
  const confirmationDialog = useRef<HTMLDialogElement | null>(null);
  const confirmationTrigger = useRef<HTMLButtonElement | null>(null);
  const mounted = useRef(false);
  const historyLoadRunId = useRef<string | null>(null);
  const currentRunId = useRef(run.run_id);
  currentRunId.current = run.run_id;

  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; };
  }, []);

  useEffect(() => {
    const runId = run.run_id;
    if (historyLoadRunId.current === runId) return;
    historyLoadRunId.current = runId;
    api.listLabExecutions(runId).then((items) => {
      if (!mounted.current || currentRunId.current !== runId) return;
      setHistory((current) => mergeExecutions(items, current));
    }).catch(() => {
      if (mounted.current && currentRunId.current === runId) {
        setError("执行历史暂不可用，请稍后重试。");
      }
    });
  }, [run.run_id]);

  async function previewTool(toolId: LabToolId) {
    if (busy) return;
    const runId = run.run_id;
    setBusy({ toolId, kind: "preview" });
    setError(null);
    try {
      const result = await api.dryRunLabTool(runId, toolId, false);
      if (!mounted.current || currentRunId.current !== runId) return;
      const preview = result.tool_results.find((item) => item.tool_id === toolId);
      if (preview) {
        setPreviewResults((current) => new Map(current).set(toolId, preview));
      }
    } catch {
      if (mounted.current && currentRunId.current === runId) setError("工具预览暂不可用，请重试。");
    } finally {
      if (mounted.current && currentRunId.current === runId) setBusy(null);
    }
  }

  async function executeTool(toolId: LabToolId) {
    if (busy) return;
    const runId = run.run_id;
    const idempotencyKey = retryKeys.current.get(toolId) ?? crypto.randomUUID();
    retryKeys.current.set(toolId, idempotencyKey);
    setConfirmation(null);
    setBusy({ toolId, kind: "execute" });
    setError(null);
    try {
      const executed = await api.executeLabTool(runId, toolId, idempotencyKey);
      if (!mounted.current || currentRunId.current !== runId) return;
      retryKeys.current.delete(toolId);
      setHistory((current) => mergeExecutions([executed], current));
    } catch {
      if (mounted.current && currentRunId.current === runId) {
        setError("平台内部执行暂不可用，请重试。");
      }
    } finally {
      if (mounted.current && currentRunId.current === runId) setBusy(null);
    }
  }

  const confirmationPlan = confirmation
    ? run.tool_plans.find((plan) => plan.tool_id === confirmation)
    : null;

  useEffect(() => {
    const dialog = confirmationDialog.current;
    if (!confirmationPlan || !dialog) return;
    if (typeof dialog.showModal === "function") {
      if (!dialog.open) dialog.showModal();
    } else {
      dialog.setAttribute("open", "");
    }
    return () => {
      if (typeof dialog.close === "function" && dialog.open) dialog.close();
      else dialog.removeAttribute("open");
      confirmationTrigger.current?.focus();
    };
  }, [confirmationPlan]);

  return (
    <section className="lab-tool-center" aria-label="工具执行中心" hidden={hidden}>
      <header className="lab-tool-center-heading">
        <div>
          <ShieldCheck size={18} />
          <div><strong>固定处置工具</strong><span>预览与平台内部执行分离</span></div>
        </div>
        <span className="lab-tool-scope">平台内部执行</span>
      </header>

      {error ? <div className="lab-tool-error" role="status"><CircleAlert size={15} />{error}</div> : null}

      <div className="lab-tool-list">
        {run.tool_plans.map((plan) => {
          const ToolIcon = toolIcons[plan.tool_id];
          const preview = previewResults.get(plan.tool_id);
          const previewStatus = preview
            ? preview.status === "succeeded" ? "预览完成" : "预览失败"
            : "预览";
          const isPreviewing = busy?.toolId === plan.tool_id && busy.kind === "preview";
          const isExecuting = busy?.toolId === plan.tool_id && busy.kind === "execute";
          return (
            <article aria-label={plan.title} key={plan.tool_id}>
              <div className="lab-tool-identity"><ToolIcon size={18} aria-hidden="true" /></div>
              <div className="lab-tool-copy">
                <strong>{plan.title}</strong>
                <p>{preview?.artifact_summary ?? plan.artifact_summary}</p>
                <div className="lab-tool-statuses">
                  <span className={preview?.status === "failed" ? "failed" : "preview"}>{previewStatus}</span>
                  <span className="internal">平台内部执行</span>
                </div>
              </div>
              <div className="lab-tool-actions">
                <button
                  type="button"
                  className="lab-tool-preview"
                  aria-label={`${isPreviewing ? "正在预览" : "预览"}${plan.title}`}
                  title={`预览${plan.title}`}
                  onClick={() => previewTool(plan.tool_id)}
                  disabled={busy !== null}
                >
                  {isPreviewing ? <LoaderCircle className="lab-tool-spinner" size={17} /> : <Eye size={17} />}
                </button>
                <button
                  type="button"
                  className="lab-tool-execute"
                  aria-label={`${isExecuting ? "正在执行" : "确认执行"}${plan.title}`}
                  onClick={(event) => {
                    confirmationTrigger.current = event.currentTarget;
                    setConfirmation(plan.tool_id);
                  }}
                  disabled={busy !== null}
                >
                  {isExecuting ? <LoaderCircle className="lab-tool-spinner" size={16} /> : <Play size={16} />}
                  <span>{isExecuting ? "正在执行" : "确认执行"}</span>
                </button>
              </div>
            </article>
          );
        })}
      </div>

      <div className="lab-receipt-ledger">
        <div className="lab-receipt-heading">
          <strong>回执账本</strong>
          <span>{history.length ? `${history.length} 条可验证记录` : "等待平台内部执行"}</span>
        </div>
        {history.length ? history.map((item) => (
          <article className={`lab-receipt-row ${item.status}`} key={item.execution_id}>
            <span className="lab-receipt-status" aria-label={item.status === "succeeded" ? "执行成功" : "执行未完成"}>
              {item.status === "succeeded" ? <ShieldCheck size={16} /> : <CircleAlert size={16} />}
            </span>
            <dl>
              <div><dt>回执</dt><dd>{item.receipt_id ?? "未生成"}</dd></div>
              <div><dt>有效动作</dt><dd>{decisionLabels[item.effective_action]}</dd></div>
              <div><dt>执行时间</dt><dd>{formatTimestamp(item.created_at)}</dd></div>
              <div><dt>SHA-256</dt><dd>{item.evidence_sha256 ?? "--"}</dd></div>
            </dl>
            {item.artifact_id ? (
              <a className="lab-artifact-download" href={api.labArtifactDownloadUrl(item.artifact_id)}>
                <FileDown size={16} />下载证据包
              </a>
            ) : <span className="lab-artifact-placeholder" aria-hidden="true" />}
          </article>
        )) : <div className="lab-receipt-empty">执行后将在此记录回执、有效动作、时间与证据摘要。</div>}
      </div>

      {confirmationPlan ? (
        <dialog
          ref={confirmationDialog}
          className="lab-confirm-dialog"
          aria-labelledby="lab-confirm-title"
          onCancel={(event) => {
            event.preventDefault();
            setConfirmation(null);
          }}
          onKeyDown={(event) => {
            if (event.key === "Escape") setConfirmation(null);
          }}
        >
          <div className="lab-confirm-icon"><ShieldCheck size={20} /></div>
          <div>
            <h2 id="lab-confirm-title">确认平台内部执行</h2>
            <p>“{confirmationPlan.title}”仅在本平台内部执行，并生成可验证回执。</p>
          </div>
          <div className="lab-confirm-actions">
            <button type="button" className="lab-confirm-cancel" autoFocus onClick={() => setConfirmation(null)}>取消</button>
            <button type="button" className="lab-confirm-submit" onClick={() => executeTool(confirmationPlan.tool_id)}>
              <Play size={16} />仅在平台内部执行
            </button>
          </div>
        </dialog>
      ) : null}
    </section>
  );
}
