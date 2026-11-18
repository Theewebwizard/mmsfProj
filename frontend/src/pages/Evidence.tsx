import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Download, FileCheck2, Fingerprint, Loader2, Send, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "@/api/client";
import type {
  CustodyTimeline,
  EvidenceDetail,
  InclusionProof,
  IntegrityResult,
  VerificationReport,
} from "@/api/types";
import { useAuth, useUsers } from "@/auth";
import { AuthImage, C2PABadge, ChecksList, EmptyState, ErrorNote, HashText, KV, StatusBadge } from "@/components/common";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Label, Select } from "@/components/ui/input";
import { downloadBlob, fmtBytes, fmtDate } from "@/lib/utils";

const EVENT_LABEL: Record<string, string> = {
  EVIDENCE_REGISTERED: "Registered",
  CUSTODY_TRANSFER_INITIATED: "Transfer initiated",
  CUSTODY_TRANSFER_ACKNOWLEDGED: "Transfer acknowledged",
  EVIDENCE_VERIFIED: "Verified",
  REPORT_EXPORTED: "Bundle exported",
};

function useInvalidate(id: string) {
  const qc = useQueryClient();
  return () => {
    qc.invalidateQueries({ queryKey: ["evidence-detail", id] });
    qc.invalidateQueries({ queryKey: ["custody", id] });
    qc.invalidateQueries({ queryKey: ["proof", id] });
    qc.invalidateQueries({ queryKey: ["log-stats"] });
  };
}

function MetadataPanel({ ev }: { ev: EvidenceDetail }) {
  const exif = Object.entries(ev.exif ?? {}).filter(([k]) => !k.startsWith("_"));
  const img = (ev.exif?._image ?? null) as Record<string, unknown> | null;
  const c2 = ev.c2pa_summary;
  return (
    <div className="grid gap-4 md:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle>Metadata / EXIF</CardTitle>
          <CardDescription>Extracted at registration. Metadata is easily stripped or forged — treat it as a lead.</CardDescription>
        </CardHeader>
        <CardContent className="max-h-72 overflow-auto">
          {img && <KV k="Dimensions">{String(img.width)} × {String(img.height)} · {String(img.mode)} · {String(img.format)}</KV>}
          {exif.length === 0 ? (
            <p className="text-sm text-muted-foreground">No EXIF metadata present.</p>
          ) : (
            exif.map(([k, v]) => (
              <KV key={k} k={k}>
                <span className="font-mono text-xs">{typeof v === "object" ? JSON.stringify(v) : String(v)}</span>
              </KV>
            ))
          )}
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>C2PA Content Credentials</CardTitle>
            <C2PABadge status={ev.c2pa_status} />
          </div>
          <CardDescription>
            {ev.c2pa_status === "ABSENT"
              ? "No manifest found. ABSENT does not mean manipulated — most sharing pipelines strip manifests."
              : ev.c2pa_status === "ERROR"
                ? "c2patool could not inspect this file (see error)."
                : "Normalised c2patool report."}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {c2 ? (
            <>
              {c2.signer && <KV k="Signer">{c2.signer}</KV>}
              {c2.issuer && <KV k="Issuer">{c2.issuer}</KV>}
              {c2.trusted !== null && <KV k="Trust list">{c2.trusted ? "trusted" : "not on trust list"}</KV>}
              {c2.signed_at && <KV k="Signed at">{c2.signed_at}</KV>}
              {c2.claim_generator && <KV k="Generator">{c2.claim_generator}</KV>}
              {c2.assertions.length > 0 && (
                <KV k="Assertions">
                  <span className="flex flex-wrap gap-1">{c2.assertions.map((a) => <Badge key={a}>{a}</Badge>)}</span>
                </KV>
              )}
              {c2.validation_codes.length > 0 && <KV k="Validation">{c2.validation_codes.join(", ")}</KV>}
              {c2.error && <KV k="Error"><span className="text-xs">{c2.error}</span></KV>}
            </>
          ) : (
            <p className="text-sm text-muted-foreground">No C2PA report stored.</p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function IntegrityPanel({ ev }: { ev: EvidenceDetail }) {
  const inv = useInvalidate(ev.id);
  const integ = useMutation({
    mutationFn: () => api.post<IntegrityResult>(`/evidence/${ev.id}/verify-integrity`),
    onSuccess: inv,
  });
  const full = useMutation({
    mutationFn: () => api.post<VerificationReport>(`/evidence/${ev.id}/verify`),
  });
  return (
    <Card>
      <CardHeader>
        <CardTitle>Integrity & TrustChain verification</CardTitle>
        <CardDescription>SHA-256 proves byte-level integrity against the registered digest — not that the content is true.</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <div className="flex flex-wrap gap-2">
          <Button onClick={() => integ.mutate()} disabled={integ.isPending}>
            {integ.isPending ? <Loader2 className="animate-spin" /> : <Fingerprint />} Verify Byte Integrity
          </Button>
          <Button variant="outline" onClick={() => full.mutate()} disabled={full.isPending}>
            {full.isPending ? <Loader2 className="animate-spin" /> : <ShieldCheck />} Run full TrustChain verification
          </Button>
        </div>
        <ErrorNote error={integ.error || full.error} />
        {integ.data && (
          <div className="rounded-md border p-3">
            <div className="mb-1 flex items-center gap-2 text-sm font-medium">
              Live MinIO re-hash <StatusBadge status={integ.data.status} />
            </div>
            <KV k="Registered">{<HashText value={integ.data.stored_digest} n={20} />}</KV>
            <KV k="Recomputed">{<HashText value={integ.data.computed_digest} n={20} />}</KV>
            <KV k="Logged as">event #{integ.data.log_index ?? "—"} (EVIDENCE_VERIFIED)</KV>
          </div>
        )}
        {full.data && (
          <div className="flex flex-col gap-2">
            <div className="flex items-center gap-2 text-sm font-medium">
              Overall <StatusBadge status={full.data.overall} />
            </div>
            <ChecksList checks={full.data.checks} />
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function CustodyPanel({ ev }: { ev: EvidenceDetail }) {
  const { user } = useAuth();
  const users = useUsers();
  const inv = useInvalidate(ev.id);
  const tl = useQuery({ queryKey: ["custody", ev.id], queryFn: () => api.get<CustodyTimeline>(`/evidence/${ev.id}/custody`) });
  const [to, setTo] = useState("");
  const [reason, setReason] = useState("");
  const [note, setNote] = useState("");
  const transfer = useMutation({
    mutationFn: () => api.post(`/evidence/${ev.id}/custody/transfer`, { to_user_id: to, reason }),
    onSuccess: () => {
      setReason("");
      inv();
    },
  });
  const ack = useMutation({
    mutationFn: () => api.post(`/evidence/${ev.id}/custody/acknowledge`, { note }),
    onSuccess: inv,
  });
  const name = (id: string | null) => users.data?.find((u) => u.id === id)?.full_name ?? (id ? id.slice(0, 8) : "—");
  const state = ev.custody;
  const isCustodian = state.custodian_id === user?.id;
  const isRecipient = state.pending_transfer_to === user?.id;

  return (
    <Card>
      <CardHeader>
        <CardTitle>Chain of custody</CardTitle>
        <CardDescription>
          Custodian: <span className="font-medium text-foreground">{name(state.custodian_id)}</span>
          {state.pending_transfer_to && <> · pending transfer to <span className="font-medium text-foreground">{name(state.pending_transfer_to)}</span></>}
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <ErrorNote error={tl.error} />
        <ol className="relative flex flex-col gap-3 border-l pl-4">
          {tl.data?.events.map((e) => (
            <li key={e.id} className="relative">
              <span className="absolute -left-[21px] top-1.5 size-2.5 rounded-full border-2 border-card bg-primary" />
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-sm font-medium">{EVENT_LABEL[e.event_type] ?? e.event_type}</span>
                <span className="font-mono text-xs text-muted-foreground">#{e.log_index}</span>
                <StatusBadge status={e.signature_valid ? "PASS" : "FAIL"} label="Ed25519" />
                <StatusBadge status={e.inclusion_valid === undefined ? "INCONCLUSIVE" : e.inclusion_valid ? "PASS" : "FAIL"} label="Merkle" />
              </div>
              <div className="text-xs text-muted-foreground">{fmtDate(e.timestamp)} · by {name(e.actor_id)} · key {e.key_id}</div>
              {e.payload && (
                <pre className="mt-1 max-h-32 overflow-auto rounded bg-muted p-2 font-mono text-[11px] leading-snug">
                  {JSON.stringify(e.payload, null, 2)}
                </pre>
              )}
            </li>
          ))}
        </ol>

        {user?.role === "INVESTIGATOR" && isCustodian && !state.pending_transfer_to && (
          <form
            className="grid gap-2 rounded-md border p-3 sm:grid-cols-[1fr_1fr_auto] sm:items-end"
            onSubmit={(e) => {
              e.preventDefault();
              transfer.mutate();
            }}
          >
            <div className="flex flex-col gap-1">
              <Label htmlFor="to">Transfer custody to</Label>
              <Select id="to" required value={to} onChange={(e) => setTo(e.target.value)}>
                <option value="">Select user…</option>
                {users.data?.filter((u) => u.id !== user.id).map((u) => (
                  <option key={u.id} value={u.id}>{u.full_name} ({u.role.toLowerCase()})</option>
                ))}
              </Select>
            </div>
            <div className="flex flex-col gap-1">
              <Label htmlFor="reason">Reason</Label>
              <Input id="reason" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="e.g. lab analysis" />
            </div>
            <Button type="submit" size="sm" disabled={!to || transfer.isPending}><Send /> Initiate</Button>
            <div className="sm:col-span-3"><ErrorNote error={transfer.error} /></div>
          </form>
        )}
        {isRecipient && (
          <form
            className="flex flex-col gap-2 rounded-md border border-warn/50 p-3 sm:flex-row sm:items-end"
            onSubmit={(e) => {
              e.preventDefault();
              ack.mutate();
            }}
          >
            <div className="flex flex-1 flex-col gap-1">
              <Label htmlFor="note">A transfer is addressed to you — acknowledge receipt</Label>
              <Input id="note" value={note} onChange={(e) => setNote(e.target.value)} placeholder="Note (optional)" />
            </div>
            <Button type="submit" size="sm" disabled={ack.isPending}><FileCheck2 /> Acknowledge</Button>
            <ErrorNote error={ack.error} />
          </form>
        )}
      </CardContent>
    </Card>
  );
}

function ProofPanel({ ev }: { ev: EvidenceDetail }) {
  const tl = useQuery({ queryKey: ["custody", ev.id], queryFn: () => api.get<CustodyTimeline>(`/evidence/${ev.id}/custody`) });
  const cp = tl.data?.checkpoint ?? null;
  const proof = useQuery({
    queryKey: ["proof", ev.id, cp?.tree_size],
    queryFn: () => api.get<{ tree_size: number; proofs: InclusionProof[] }>(`/evidence/${ev.id}/proof?tree_size=${cp!.tree_size}`),
    enabled: !!cp,
  });
  const [sel, setSel] = useState(0);
  const p = proof.data?.proofs[sel];
  return (
    <Card>
      <CardHeader>
        <CardTitle>Merkle inclusion proof inspector</CardTitle>
        <CardDescription>RFC 9162 audit path from each event's leaf to the signed tree head.</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {!cp ? (
          <EmptyState>No signed checkpoint covers this evidence yet.</EmptyState>
        ) : (
          <>
            <div className="flex flex-wrap gap-1">
              {proof.data?.proofs.map((x, i) => (
                <Button key={x.event_id} size="sm" variant={i === sel ? "default" : "outline"} onClick={() => setSel(i)}>
                  #{x.log_index} {EVENT_LABEL[x.event_type] ?? x.event_type}
                </Button>
              ))}
            </div>
            {p && (
              <div className="rounded-md border p-3">
                <KV k="Log index">{p.log_index}</KV>
                <KV k="Tree size">{p.tree_size}</KV>
                <KV k="Leaf hash"><HashText value={p.leaf_hash} n={20} /></KV>
                <KV k="Audit path">
                  {p.proof.length === 0 ? (
                    <span className="text-xs text-muted-foreground">empty (single-leaf tree)</span>
                  ) : (
                    <ol className="flex flex-col gap-0.5">
                      {p.proof.map((h, i) => (
                        <li key={i} className="font-mono text-xs"><span className="text-muted-foreground">{i}:</span> <HashText value={h} n={16} /></li>
                      ))}
                    </ol>
                  )}
                </KV>
                <KV k="Root"><HashText value={p.root_hash} n={20} /></KV>
              </div>
            )}
            <div className="rounded-md border p-3">
              <div className="mb-1 text-sm font-medium">Signed checkpoint</div>
              <KV k="Log">{cp.log_id}</KV>
              <KV k="Tree size">{cp.tree_size}</KV>
              <KV k="Root hash"><HashText value={cp.root_hash} n={20} /></KV>
              <KV k="Timestamp">{cp.timestamp}</KV>
              <KV k="Log key id"><span className="font-mono text-xs">{cp.key_id}</span></KV>
              <KV k="Signature"><HashText value={cp.signature} n={16} /></KV>
              <KV k="Witness"><StatusBadge status={cp.witness.status} /></KV>
              {cp.witness.key_id && <KV k="Witness key id"><span className="font-mono text-xs">{cp.witness.key_id}</span></KV>}
              {cp.witness.signature && <KV k="Co-signature"><HashText value={cp.witness.signature} n={16} /></KV>}
              {cp.witness.alert && <KV k="Alert"><span className="text-fail">{cp.witness.alert}</span></KV>}
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

function ExportPanel({ ev }: { ev: EvidenceDetail }) {
  const inv = useInvalidate(ev.id);
  const m = useMutation({
    mutationFn: () => api.blob(`/evidence/${ev.id}/bundle`, "POST"),
    onSuccess: (b) => {
      downloadBlob(b, `trustchain-bundle-${ev.id}.json`);
      inv();
    },
  });
  return (
    <Card>
      <CardHeader>
        <CardTitle>Offline verification bundle</CardTitle>
        <CardDescription>Records a signed REPORT_EXPORTED event, then exports every proof needed to verify without this server.</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <Button className="self-start" onClick={() => m.mutate()} disabled={m.isPending}>
          {m.isPending ? <Loader2 className="animate-spin" /> : <Download />} Export Verification Bundle (JSON)
        </Button>
        <ErrorNote error={m.error} />
        <pre className="overflow-x-auto rounded bg-muted p-2 font-mono text-xs">
{`cd cli && python -m trustchain_verify verify \\
  --file ${ev.original_filename} \\
  --bundle trustchain-bundle-${ev.id}.json \\
  --log-key <checkpoint pubkey> --witness-key <witness pubkey>`}
        </pre>
        <p className="text-xs text-muted-foreground">
          Pin the log and witness public keys obtained out-of-band (e.g. <span className="font-mono">keys/public.json</span>);
          keys embedded in the bundle only prove internal consistency.
        </p>
      </CardContent>
    </Card>
  );
}

export default function EvidencePage() {
  const { id = "" } = useParams();
  const ev = useQuery({ queryKey: ["evidence-detail", id], queryFn: () => api.get<EvidenceDetail>(`/evidence/${id}`) });
  if (ev.isLoading) return <p className="text-sm text-muted-foreground">Loading…</p>;
  if (ev.error || !ev.data) return <ErrorNote error={ev.error ?? "not found"} />;
  const e = ev.data;
  return (
    <div className="flex flex-col gap-6">
      <div>
        <Link to="/cases" className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground">
          <ArrowLeft className="size-3" /> Vault
        </Link>
        <h1 className="mt-1 text-lg font-semibold break-all">{e.original_filename}</h1>
      </div>
      <div className="grid gap-4 lg:grid-cols-[minmax(0,420px)_1fr]">
        <Card className="overflow-hidden">
          <AuthImage path={`/evidence/${e.id}/content`} alt={e.original_filename} className="h-80 w-full bg-muted" />
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Registered record</CardTitle>
          </CardHeader>
          <CardContent>
            <KV k="Evidence id"><span className="font-mono text-xs">{e.id}</span></KV>
            <KV k="SHA-256"><HashText value={e.sha256_digest} n={24} /></KV>
            <KV k="pHash"><span className="font-mono text-xs">{e.phash ?? "—"}</span></KV>
            <KV k="Type / size">{e.mime_type} · {fmtBytes(e.file_size)}</KV>
            <KV k="Storage key"><span className="font-mono text-xs">{e.storage_key}</span></KV>
            <KV k="Log index">{e.registration_log_index ?? "—"}</KV>
            <KV k="Registered">{fmtDate(e.created_at)}</KV>
            <KV k="C2PA"><C2PABadge status={e.c2pa_status} /></KV>
          </CardContent>
        </Card>
      </div>
      <MetadataPanel ev={e} />
      <IntegrityPanel ev={e} />
      <div className="grid gap-4 xl:grid-cols-2">
        <CustodyPanel ev={e} />
        <ProofPanel ev={e} />
      </div>
      <ExportPanel ev={e} />
    </div>
  );
}
