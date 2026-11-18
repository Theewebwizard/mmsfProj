import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, Check, CheckCircle2, CircleHelp, Copy, ImageOff, Upload, XCircle } from "lucide-react";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { api } from "@/api/client";
import type { Check as CheckT, CheckStatus } from "@/api/types";
import { Badge } from "@/components/ui/badge";
import { cn, shortHash } from "@/lib/utils";

type Tone = "neutral" | "pass" | "fail" | "warn" | "info";

const STATUS_TONE: Record<string, Tone> = {
  PASS: "pass",
  VALID: "pass",
  ACKNOWLEDGED: "pass",
  ACCEPTED: "pass",
  VERIFIED_REGISTERED_ORIGINAL: "pass",
  FAIL: "fail",
  INVALID: "fail",
  REJECTED: "fail",
  INTEGRITY_FAILURE: "fail",
  INCONCLUSIVE: "warn",
  UNAVAILABLE: "warn",
  CANDIDATE_ONLY: "warn",
  PENDING: "warn",
  ERROR: "warn",
  ABSENT: "neutral",
  NO_MATCH: "neutral",
};

export function StatusBadge({ status, label }: { status: string | null | undefined; label?: string }) {
  const s = status ?? "—";
  const tone = STATUS_TONE[s] ?? "neutral";
  const Icon = tone === "pass" ? CheckCircle2 : tone === "fail" ? XCircle : tone === "warn" ? AlertTriangle : CircleHelp;
  return (
    <Badge tone={tone}>
      <Icon />
      {label ? `${label}: ` : ""}
      {s.replaceAll("_", " ")}
    </Badge>
  );
}

export function C2PABadge({ status }: { status: string | null | undefined }) {
  return <StatusBadge status={status} label="C2PA" />;
}

export function HashText({ value, n = 12, className }: { value: string | null | undefined; n?: number; className?: string }) {
  const [copied, setCopied] = useState(false);
  if (!value) return <span className="text-muted-foreground">—</span>;
  return (
    <span className={cn("inline-flex items-center gap-1 font-mono text-xs", className)} title={value}>
      {shortHash(value, n)}
      <button
        type="button"
        aria-label="Copy"
        className="cursor-pointer text-muted-foreground hover:text-foreground"
        onClick={(e) => {
          e.preventDefault();
          e.stopPropagation();
          navigator.clipboard?.writeText(value).then(() => {
            setCopied(true);
            setTimeout(() => setCopied(false), 1200);
          });
        }}
      >
        {copied ? <Check className="size-3" /> : <Copy className="size-3" />}
      </button>
    </span>
  );
}

export function KV({ k, children }: { k: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[minmax(110px,160px)_1fr] gap-2 py-1 text-sm">
      <span className="text-xs text-muted-foreground">{k}</span>
      <span className="min-w-0 break-all">{children}</span>
    </div>
  );
}

export function ErrorNote({ error }: { error: unknown }) {
  if (!error) return null;
  return (
    <div className="rounded-md border border-fail/40 bg-fail/10 px-3 py-2 text-sm text-fail">
      {error instanceof Error ? error.message : String(error)}
    </div>
  );
}

export function EmptyState({ children }: { children: ReactNode }) {
  return <div className="rounded-md border border-dashed p-6 text-center text-sm text-muted-foreground">{children}</div>;
}

/** Image served by an authenticated endpoint (fetched as a blob). */
export function AuthImage({ path, alt, className }: { path: string; alt: string; className?: string }) {
  const q = useQuery({
    queryKey: ["blob", path],
    queryFn: async () => URL.createObjectURL(await api.blob(path)),
    staleTime: Infinity,
  });
  if (q.isLoading) return <div className={cn("animate-pulse bg-muted", className)} />;
  if (q.isError || !q.data)
    return (
      <div className={cn("flex items-center justify-center bg-muted text-muted-foreground", className)}>
        <ImageOff className="size-6" />
      </div>
    );
  return <img src={q.data} alt={alt} className={cn("object-contain", className)} />;
}

export function useObjectUrl(file: File | null) {
  const [url, setUrl] = useState<string | null>(null);
  useEffect(() => {
    if (!file) return setUrl(null);
    const u = URL.createObjectURL(file);
    setUrl(u);
    return () => URL.revokeObjectURL(u);
  }, [file]);
  return url;
}

export function Dropzone({
  onFile,
  disabled,
  hint,
}: {
  onFile: (f: File) => void;
  disabled?: boolean;
  hint?: string;
}) {
  const ref = useRef<HTMLInputElement>(null);
  const [over, setOver] = useState(false);
  return (
    <div
      role="button"
      tabIndex={0}
      aria-disabled={disabled}
      onClick={() => !disabled && ref.current?.click()}
      onKeyDown={(e) => e.key === "Enter" && !disabled && ref.current?.click()}
      onDragOver={(e) => {
        e.preventDefault();
        if (!disabled) setOver(true);
      }}
      onDragLeave={() => setOver(false)}
      onDrop={(e) => {
        e.preventDefault();
        setOver(false);
        const f = e.dataTransfer.files?.[0];
        if (f && !disabled) onFile(f);
      }}
      className={cn(
        "flex cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border-2 border-dashed p-6 text-center text-sm transition-colors",
        over ? "border-primary bg-primary/5" : "hover:bg-muted/50",
        disabled && "cursor-not-allowed opacity-50",
      )}
    >
      <Upload className="size-5 text-muted-foreground" />
      <span className="font-medium">Drop an image or click to browse</span>
      <span className="text-xs text-muted-foreground">{hint ?? "JPEG, PNG or WebP · validated by magic bytes on the server"}</span>
      <input
        ref={ref}
        type="file"
        accept="image/jpeg,image/png,image/webp"
        className="hidden"
        onChange={(e) => {
          const f = e.target.files?.[0];
          if (f) onFile(f);
          e.target.value = "";
        }}
      />
    </div>
  );
}

const CHECK_LABELS: Record<string, string> = {
  STORAGE_SHA256: "Stored original SHA-256 (live MinIO re-hash)",
  REGISTRATION_BINDING: "Signed registration binds digest",
  EVENT_SIGNATURES: "Ed25519 custody-event signatures",
  EVENT_HASH_CHAIN: "Per-evidence event hash chain",
  MERKLE_INCLUSION: "RFC 9162 Merkle inclusion",
  CHECKPOINT_SIGNATURE: "Signed checkpoint (STH)",
  WITNESS_COSIGNATURE: "Independent witness co-signature",
};

export function ChecksList({ checks }: { checks: CheckT[] }) {
  return (
    <ul className="divide-y rounded-md border">
      {checks.map((c) => (
        <li key={c.name} className="flex flex-col gap-1 px-3 py-2 sm:flex-row sm:items-start sm:justify-between">
          <div className="min-w-0">
            <div className="text-sm font-medium">{CHECK_LABELS[c.name] ?? c.name}</div>
            <div className="text-xs break-words text-muted-foreground">{c.detail}</div>
          </div>
          <StatusBadge status={c.status as CheckStatus} />
        </li>
      ))}
    </ul>
  );
}
