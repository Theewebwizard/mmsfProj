import { useMutation } from "@tanstack/react-query";
import { AlertTriangle, Info, Loader2, Search, ShieldCheck } from "lucide-react";
import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { api } from "@/api/client";
import type { Assessment, TraceCandidate, TraceSearchResult, VerifyCandidateResult } from "@/api/types";
import { useAuth } from "@/auth";
import { AuthImage, ChecksList, Dropzone, ErrorNote, HashText, KV, StatusBadge, useObjectUrl } from "@/components/common";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Label, Slider, Switch } from "@/components/ui/input";
import { cn, fmtBytes } from "@/lib/utils";

const BANNER: Record<Assessment, { cls: string; title: string }> = {
  VERIFIED_REGISTERED_ORIGINAL: { cls: "border-pass/50 bg-pass/10 text-pass", title: "Verified registered original" },
  CANDIDATE_ONLY: { cls: "border-warn/60 bg-warn/15 text-warn", title: "Candidate only" },
  INTEGRITY_FAILURE: { cls: "border-fail/50 bg-fail/10 text-fail", title: "Integrity failure" },
  NO_MATCH: { cls: "border-border bg-muted text-muted-foreground", title: "No match" },
};

function AssessmentBanner({ a, children }: { a: Assessment; children: ReactNode }) {
  const b = BANNER[a];
  return (
    <div className={cn("rounded-lg border-2 p-4", b.cls)}>
      <div className="flex items-center gap-2 text-base font-semibold">
        {a === "VERIFIED_REGISTERED_ORIGINAL" ? <ShieldCheck className="size-5" /> : <AlertTriangle className="size-5" />}
        {b.title} <span className="font-mono text-xs opacity-80">{a}</span>
      </div>
      <div className="mt-1 text-sm text-foreground">{children}</div>
    </div>
  );
}

const RELATIONSHIP: Record<string, string> = {
  BYTE_IDENTICAL: "Query is byte-identical (SHA-256) to the registered original",
  PERCEPTUAL_CANDIDATE: "Perceptual (pHash) similarity only — not proof of derivation",
  GEOMETRIC_CANDIDATE: "Local-feature (ORB + RANSAC) geometric overlap only — not proof of derivation",
  NONE: "No similarity relationship established",
};

function CandidateRow({
  c,
  rank,
  queryUrl,
  file,
  threshold,
  minInliers,
}: {
  c: TraceCandidate;
  rank: number;
  queryUrl: string;
  file: File;
  threshold: number;
  minInliers: number;
}) {
  const verify = useMutation({
    mutationFn: () => {
      const fd = new FormData();
      fd.append("file", file);
      fd.append("evidence_id", c.evidence_id);
      fd.append("phash_threshold", String(threshold));
      fd.append("orb_min_inliers", String(minInliers));
      return api.postForm<VerifyCandidateResult>("/trace/verify-candidate", fd);
    },
  });
  const v = verify.data;
  return (
    <Card>
      <CardHeader className="flex-row flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <Badge tone="info">#{rank}</Badge>
          <Link className="text-sm font-medium text-primary hover:underline" to={`/evidence/${c.evidence_id}`}>
            {c.evidence.original_filename}
          </Link>
          {c.matched_by.map((m) => <Badge key={m}>{m.replaceAll("_", " ")}</Badge>)}
        </div>
        <Button size="sm" onClick={() => verify.mutate()} disabled={verify.isPending}>
          {verify.isPending ? <Loader2 className="animate-spin" /> : <ShieldCheck />} Verify Candidate Provenance
        </Button>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div className="grid gap-4 md:grid-cols-[1fr_1fr_minmax(220px,0.9fr)]">
          <figure>
            <img src={queryUrl} alt="query" className="h-48 w-full rounded-md bg-muted object-contain" />
            <figcaption className="mt-1 text-xs text-muted-foreground">Query (unregistered)</figcaption>
          </figure>
          <figure>
            <AuthImage path={`/evidence/${c.evidence_id}/content`} alt="candidate" className="h-48 w-full rounded-md bg-muted" />
            <figcaption className="mt-1 text-xs text-muted-foreground">Registered original (from vault)</figcaption>
          </figure>
          <div className="text-sm">
            <KV k="SHA-256 match">{c.sha256_match ? <StatusBadge status="PASS" /> : <span className="text-muted-foreground">no</span>}</KV>
            <KV k="Hamming">{c.hamming ?? "—"} / 64</KV>
            <KV k="pHash similarity">{c.phash_similarity !== null ? `${(c.phash_similarity * 100).toFixed(1)}%` : "—"}</KV>
            {c.orb && (
              <>
                <KV k="ORB inliers">{c.orb.inliers} <span className="text-xs text-muted-foreground">of {c.orb.good_matches} ratio-test matches</span></KV>
                <KV k="Homography">{c.orb.homography_found ? "found" : "none"}</KV>
              </>
            )}
            <KV k="Registered SHA-256"><HashText value={c.evidence.sha256_digest} n={8} /></KV>
          </div>
        </div>
        <ErrorNote error={verify.error} />
        {v && (
          <div className="flex flex-col gap-3">
            <AssessmentBanner a={v.assessment}>
              <p>{v.explanation}</p>
              <p className="mt-1 text-xs text-muted-foreground">Relationship: <span className="font-mono">{v.relationship}</span> — {RELATIONSHIP[v.relationship]}</p>
            </AssessmentBanner>
            {v.assessment !== "NO_MATCH" && <ChecksList checks={v.verification.checks} />}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export default function TracePage() {
  const { user } = useAuth();
  const canSearch = user?.role === "INVESTIGATOR";
  const [file, setFile] = useState<File | null>(null);
  const url = useObjectUrl(file);
  const [exactOnly, setExactOnly] = useState(false);
  const [threshold, setThreshold] = useState(10);
  const [useOrb, setUseOrb] = useState(false);
  const [topK, setTopK] = useState(10);
  const [minInliers, setMinInliers] = useState(15);

  const search = useMutation({
    mutationFn: (f: File) => {
      const fd = new FormData();
      fd.append("file", f);
      fd.append("exact_only", String(exactOnly));
      fd.append("phash_threshold", String(threshold));
      fd.append("use_orb", String(useOrb));
      fd.append("orb_top_k", String(topK));
      fd.append("orb_min_inliers", String(minInliers));
      return api.postForm<TraceSearchResult>("/trace/search", fd);
    },
  });
  const r = search.data;

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-lg font-semibold">MediaTrace & Provenance Recovery</h1>
        <p className="text-sm text-muted-foreground">
          Upload a stripped or transformed copy to find registered candidates, then verify a candidate's record cryptographically.
        </p>
      </div>
      {!canSearch && (
        <div className="flex items-start gap-2 rounded-md border border-warn/50 bg-warn/10 p-3 text-sm">
          <Info className="mt-0.5 size-4 shrink-0 text-warn" />
          Searching is restricted to investigators. Auditors can verify evidence records from the Evidence Inspector.
        </div>
      )}
      <div className="grid gap-4 lg:grid-cols-[1fr_360px]">
        <Card>
          <CardHeader>
            <CardTitle>Query image</CardTitle>
            <CardDescription>The query is analysed in memory and is not registered or stored.</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-4 md:grid-cols-2">
            <Dropzone onFile={(f) => { setFile(f); search.reset(); }} disabled={!canSearch} />
            {url && file ? (
              <figure>
                <img src={url} alt="query preview" className="h-48 w-full rounded-md bg-muted object-contain" />
                <figcaption className="mt-1 text-xs text-muted-foreground">{file.name} · {fmtBytes(file.size)}</figcaption>
              </figure>
            ) : (
              <div className="flex h-48 items-center justify-center rounded-md bg-muted text-xs text-muted-foreground">No query selected</div>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Search mode</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <div className="flex items-center justify-between">
              <Label htmlFor="exact">Exact SHA-256 only</Label>
              <Switch id="exact" checked={exactOnly} onCheckedChange={setExactOnly} disabled={!canSearch} />
            </div>
            <div className={cn("flex flex-col gap-1", exactOnly && "opacity-50")}>
              <div className="flex justify-between"><Label htmlFor="thr">pHash Hamming threshold</Label><span className="font-mono text-xs">{threshold}</span></div>
              <Slider id="thr" min={0} max={32} value={threshold} onValueChange={setThreshold} disabled={exactOnly || !canSearch} />
            </div>
            <div className={cn("flex items-center justify-between", exactOnly && "opacity-50")}>
              <Label htmlFor="orb">ORB + RANSAC geometric check (crops)</Label>
              <Switch id="orb" checked={useOrb} onCheckedChange={setUseOrb} disabled={exactOnly || !canSearch} />
            </div>
            {useOrb && !exactOnly && (
              <div className="grid grid-cols-2 gap-2">
                <div className="flex flex-col gap-1">
                  <Label htmlFor="topk">Top-K to check</Label>
                  <Input id="topk" type="number" min={1} max={100} value={topK} onChange={(e) => setTopK(Number(e.target.value))} />
                </div>
                <div className="flex flex-col gap-1">
                  <Label htmlFor="inl">Min inliers</Label>
                  <Input id="inl" type="number" min={4} max={1000} value={minInliers} onChange={(e) => setMinInliers(Number(e.target.value))} />
                </div>
              </div>
            )}
            <Button onClick={() => file && search.mutate(file)} disabled={!file || !canSearch || search.isPending}>
              {search.isPending ? <Loader2 className="animate-spin" /> : <Search />} Search registered evidence
            </Button>
          </CardContent>
        </Card>
      </div>

      <ErrorNote error={search.error} />
      {r && (
        <div className="flex flex-col gap-4">
          <Card>
            <CardContent className="grid gap-x-6 sm:grid-cols-2">
              <KV k="Query SHA-256"><HashText value={r.query.sha256} n={16} /></KV>
              <KV k="Query pHash"><span className="font-mono text-xs">{r.query.phash}</span></KV>
              <KV k="Dimensions">{r.query.width} × {r.query.height} · {r.query.mime_type}</KV>
              <KV k="EXIF present">{r.query.exif_present ? "yes" : "no (stripped)"}</KV>
              <KV k="Gallery searched">{r.gallery_size} registered items</KV>
              <KV k="Time">{r.timings_ms.total.toFixed(1)} ms</KV>
            </CardContent>
          </Card>
          <div className="flex items-start gap-2 rounded-md border border-info/40 bg-info/10 p-3 text-sm">
            <Info className="mt-0.5 size-4 shrink-0 text-info" />
            {r.notice}
          </div>
          {r.outcome === "NO_MATCH" || !file || !url ? (
            <AssessmentBanner a="NO_MATCH">
              No registered evidence matched this query under the selected mode. This does not establish that the image is unregistered
              elsewhere — try enabling ORB for crops or raising the threshold (more false positives).
            </AssessmentBanner>
          ) : (
            r.candidates.map((c, i) => (
              <CandidateRow key={c.evidence_id} c={c} rank={i + 1} queryUrl={url} file={file} threshold={threshold} minInliers={minInliers} />
            ))
          )}
        </div>
      )}
    </div>
  );
}
