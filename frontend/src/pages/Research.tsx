import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, FlaskConical, Loader2, Play } from "lucide-react";
import { useEffect, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api } from "@/api/client";
import type { BenchmarkSpec, ChartSpec, ExperimentManifest, ExperimentRunSummary, ExperimentStatus } from "@/api/types";
import { EmptyState, ErrorNote } from "@/components/common";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { downloadBlob, fmtDate } from "@/lib/utils";

// Categorical palette validated for both themes (distinct hues, similar lightness).
const COLORS = ["#3b82f6", "#f59e0b", "#10b981", "#ef4444", "#8b5cf6", "#06b6d4", "#ec4899", "#84cc16"];

function fmtNum(v: unknown): string {
  if (v === null || v === undefined || v === "") return "—";
  if (typeof v === "number") return Number.isInteger(v) ? String(v) : v.toFixed(Math.abs(v) < 1 ? 4 : 2);
  return String(v);
}

function Chart({ spec }: { spec: ChartSpec }) {
  const common = (
    <>
      <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
      <XAxis
        dataKey={spec.x}
        tick={{ fontSize: 10, fill: "var(--muted-foreground)" }}
        interval={0}
        angle={spec.type === "bar" && spec.data.length > 5 ? -30 : 0}
        textAnchor={spec.type === "bar" && spec.data.length > 5 ? "end" : "middle"}
        height={spec.type === "bar" && spec.data.length > 5 ? 80 : 30}
        stroke="var(--border)"
      />
      <YAxis tick={{ fontSize: 10, fill: "var(--muted-foreground)" }} stroke="var(--border)" width={56} />
      <Tooltip
        contentStyle={{ background: "var(--card)", border: "1px solid var(--border)", fontSize: 12, color: "var(--foreground)" }}
        formatter={(v: unknown) => fmtNum(v)}
      />
      <Legend wrapperStyle={{ fontSize: 11 }} />
    </>
  );
  return (
    <div>
      <div className="mb-1 text-xs font-medium">{spec.title}</div>
      <div className="h-72 w-full">
        <ResponsiveContainer>
          {spec.type === "bar" ? (
            <BarChart data={spec.data}>
              {common}
              {spec.series.map((s, i) => (
                <Bar key={s} dataKey={s} fill={COLORS[i % COLORS.length]} radius={[2, 2, 0, 0]} />
              ))}
            </BarChart>
          ) : (
            <LineChart data={spec.data}>
              {common}
              {spec.series.map((s, i) => (
                <Line key={s} dataKey={s} stroke={COLORS[i % COLORS.length]} strokeWidth={2} dot={{ r: 2 }} type="monotone" connectNulls />
              ))}
            </LineChart>
          )}
        </ResponsiveContainer>
      </div>
      {(spec.x_label || spec.y_label) && (
        <div className="text-[11px] text-muted-foreground">
          x: {spec.x_label || spec.x}{spec.y_label ? ` · y: ${spec.y_label}` : ""}
        </div>
      )}
    </div>
  );
}

function FileButton({ runId, name }: { runId: string; name: string }) {
  const m = useMutation({
    mutationFn: () => api.blob(`/experiments/${runId}/files/${name}`),
    onSuccess: (b) => downloadBlob(b, name),
  });
  return (
    <Button size="sm" variant="outline" onClick={() => m.mutate()} disabled={m.isPending}>
      <Download /> {name}
    </Button>
  );
}

function Benchmark({ runId, spec }: { runId: string; spec: BenchmarkSpec }) {
  const cols = spec.table?.length ? Object.keys(spec.table[0]) : [];
  return (
    <Card>
      <CardHeader>
        <CardTitle>{spec.title}</CardTitle>
        <CardDescription>{spec.description}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div className="grid gap-6 xl:grid-cols-2">
          {spec.charts.map((c) => <Chart key={c.title} spec={c} />)}
        </div>
        {cols.length > 0 && (
          <details>
            <summary className="cursor-pointer text-xs text-muted-foreground">Result table ({spec.table!.length} rows)</summary>
            <Table className="mt-2 text-xs">
              <THead>
                <TR>{cols.map((c) => <TH key={c}>{c}</TH>)}</TR>
              </THead>
              <TBody>
                {spec.table!.map((row, i) => (
                  <TR key={i}>{cols.map((c) => <TD key={c} className="font-mono">{fmtNum(row[c])}</TD>)}</TR>
                ))}
              </TBody>
            </Table>
          </details>
        )}
        <div className="flex flex-wrap gap-2">
          {spec.files.filter((f) => f.endsWith(".csv")).map((f) => <FileButton key={f} runId={runId} name={f} />)}
          {spec.files.filter((f) => f.endsWith(".png")).map((f) => <FileButton key={f} runId={runId} name={f} />)}
        </div>
      </CardContent>
    </Card>
  );
}

export default function ResearchPage() {
  const qc = useQueryClient();
  const runs = useQuery({ queryKey: ["experiments"], queryFn: () => api.get<ExperimentRunSummary[]>("/experiments") });
  const status = useQuery({
    queryKey: ["experiments-status"],
    queryFn: () => api.get<ExperimentStatus>("/experiments/status"),
    refetchInterval: (q) => (q.state.data?.state === "running" ? 2000 : false),
  });
  const [selected, setSelected] = useState<string | null>(null);
  useEffect(() => {
    if (!selected && runs.data?.length) setSelected(runs.data[0].id);
  }, [runs.data, selected]);
  useEffect(() => {
    if (status.data?.state === "completed") qc.invalidateQueries({ queryKey: ["experiments"] });
  }, [status.data?.state, qc]);

  const manifest = useQuery({
    queryKey: ["experiment", selected],
    queryFn: () => api.get<ExperimentManifest>(`/experiments/${selected}`),
    enabled: !!selected,
  });
  const start = useMutation({
    mutationFn: () => api.post<{ run_id: string }>("/experiments/run", { quick: true, seed: 1337 }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["experiments-status"] }),
  });
  const running = status.data?.state === "running";
  const m = manifest.data;

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold">Research & Benchmarks</h1>
          <p className="text-sm text-muted-foreground">
            Every number below comes from a recorded run of <span className="font-mono">experiments/run_all.py</span> on a seeded synthetic dataset.
          </p>
        </div>
        <Button onClick={() => start.mutate()} disabled={running || start.isPending}>
          {running ? <Loader2 className="animate-spin" /> : <Play />} Run quick benchmark suite
        </Button>
      </div>
      <ErrorNote error={start.error || runs.error} />
      {status.data && status.data.state !== "idle" && (
        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <CardTitle>Run {status.data.run_id}</CardTitle>
              <Badge tone={status.data.state === "failed" ? "fail" : status.data.state === "completed" ? "pass" : "warn"}>{status.data.state}</Badge>
            </div>
          </CardHeader>
          {status.data.log_tail && (
            <CardContent>
              <pre className="max-h-48 overflow-auto rounded bg-muted p-2 font-mono text-[11px]">{status.data.log_tail}</pre>
            </CardContent>
          )}
        </Card>
      )}

      {runs.data?.length === 0 ? (
        <EmptyState>
          <FlaskConical className="mx-auto mb-2 size-5" />
          No completed experiment runs yet. Start one above or run <span className="font-mono">python experiments/run_all.py</span>.
        </EmptyState>
      ) : (
        <div className="flex flex-wrap gap-2">
          {runs.data?.map((r) => (
            <Button key={r.id} size="sm" variant={r.id === selected ? "default" : "outline"} onClick={() => setSelected(r.id)}>
              {r.name} · {fmtDate(r.created_at)}
            </Button>
          ))}
        </div>
      )}

      <ErrorNote error={manifest.error} />
      {m && (
        <>
          <Card>
            <CardHeader>
              <CardTitle>{m.name}</CardTitle>
              <CardDescription>
                {String(m.config.n_base_originals)} originals × {(m.config.transforms as string[] | undefined)?.length ?? "?"} transforms +{" "}
                {String(m.config.n_negatives)} negatives · seed {String(m.config.seed)} · {String(m.config.platform ?? "")}
              </CardDescription>
            </CardHeader>
            <CardContent className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
              {Object.entries(m.summary).map(([k, v]) => (
                <div key={k} className="rounded-md border p-3">
                  <div className="font-mono text-lg font-semibold">{fmtNum(v)}</div>
                  <div className="text-[11px] break-words text-muted-foreground">{k.replaceAll("_", " ")}</div>
                </div>
              ))}
            </CardContent>
          </Card>
          {Object.entries(m.benchmarks).map(([k, spec]) => <Benchmark key={k} runId={m.run_id} spec={spec} />)}
        </>
      )}
    </div>
  );
}
