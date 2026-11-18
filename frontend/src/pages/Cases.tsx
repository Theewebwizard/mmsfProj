import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Loader2, Plus } from "lucide-react";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "@/api/client";
import type { Case, EvidenceSummary } from "@/api/types";
import { useAuth } from "@/auth";
import { C2PABadge, Dropzone, EmptyState, ErrorNote, HashText, KV, StatusBadge } from "@/components/common";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Label, Textarea } from "@/components/ui/input";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { fmtBytes, fmtDate, safeStorageGet, safeStorageSet, sha256Hex } from "@/lib/utils";

function CreateCase({ onCreated }: { onCreated: (c: Case) => void }) {
  const qc = useQueryClient();
  const [title, setTitle] = useState("");
  const [desc, setDesc] = useState("");
  const m = useMutation({
    mutationFn: () => api.post<Case>("/cases", { title, description: desc || null }),
    onSuccess: (c) => {
      qc.invalidateQueries({ queryKey: ["cases"] });
      setTitle("");
      setDesc("");
      onCreated(c);
    },
  });
  return (
    <form
      className="flex flex-col gap-2"
      onSubmit={(e) => {
        e.preventDefault();
        m.mutate();
      }}
    >
      <Label htmlFor="ct">New case</Label>
      <Input id="ct" placeholder="Case title" required value={title} onChange={(e) => setTitle(e.target.value)} />
      <Textarea placeholder="Description (optional)" value={desc} onChange={(e) => setDesc(e.target.value)} />
      <ErrorNote error={m.error} />
      <Button type="submit" size="sm" disabled={m.isPending}>
        <Plus /> Create case
      </Button>
    </form>
  );
}

function Upload({ caseId }: { caseId: string }) {
  const qc = useQueryClient();
  const [file, setFile] = useState<File | null>(null);
  const [clientHash, setClientHash] = useState<string | null>(null);
  const [hashing, setHashing] = useState(false);
  const m = useMutation({
    mutationFn: (f: File) => {
      const fd = new FormData();
      fd.append("file", f);
      return api.postForm<EvidenceSummary>(`/cases/${caseId}/evidence`, fd);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["evidence", caseId] });
      qc.invalidateQueries({ queryKey: ["log-stats"] });
    },
  });

  const onFile = async (f: File) => {
    setFile(f);
    setClientHash(null);
    m.reset();
    setHashing(true);
    const h = await sha256Hex(f);
    setClientHash(h);
    setHashing(false);
    m.mutate(f);
  };

  const r = m.data;
  return (
    <div className="grid gap-4 md:grid-cols-2">
      <Dropzone onFile={onFile} disabled={m.isPending} />
      <div className="rounded-md border p-3 text-sm">
        {!file ? (
          <p className="text-muted-foreground">
            The SHA-256 is computed in your browser as soon as a file is dropped, then independently by the server, which
            signs an <span className="font-mono">EVIDENCE_REGISTERED</span> event and appends it to the Merkle log.
          </p>
        ) : (
          <div>
            <KV k="File">{file.name} · {fmtBytes(file.size)}</KV>
            <KV k="Client SHA-256">{hashing ? <Loader2 className="size-4 animate-spin" /> : <HashText value={clientHash} n={16} />}</KV>
            {m.isPending && (
              <KV k="Server">
                <span className="inline-flex items-center gap-2 text-muted-foreground">
                  <Loader2 className="size-4 animate-spin" /> registering…
                </span>
              </KV>
            )}
            <ErrorNote error={m.error} />
            {r && (
              <>
                <KV k="Server SHA-256">
                  <span className="inline-flex flex-wrap items-center gap-2">
                    <HashText value={r.sha256_digest} n={16} />
                    {clientHash && (
                      <StatusBadge status={clientHash === r.sha256_digest ? "PASS" : "FAIL"} label="client match" />
                    )}
                  </span>
                </KV>
                <KV k="C2PA"><C2PABadge status={r.c2pa_status} /></KV>
                <KV k="Merkle log index"><span className="font-mono">{r.log_index ?? "—"}</span></KV>
                <KV k="Checkpoint">
                  <span className="inline-flex items-center gap-2">
                    <span className="font-mono">tree size {r.checkpoint_tree_size ?? "—"}</span>
                    <StatusBadge status={r.witness_status} label="witness" />
                  </span>
                </KV>
                <KV k="Evidence">
                  <Link className="text-primary underline" to={`/evidence/${r.id}`}>Open in inspector →</Link>
                </KV>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export default function CasesPage() {
  const { user } = useAuth();
  const isInvestigator = user?.role === "INVESTIGATOR";
  const cases = useQuery({ queryKey: ["cases"], queryFn: () => api.get<Case[]>("/cases") });
  const [selected, setSelected] = useState<string | null>(() => safeStorageGet("tc-case"));

  useEffect(() => {
    if (cases.data && cases.data.length && !cases.data.some((c) => c.id === selected)) setSelected(cases.data[0].id);
  }, [cases.data, selected]);
  useEffect(() => safeStorageSet("tc-case", selected), [selected]);

  const evidence = useQuery({
    queryKey: ["evidence", selected],
    queryFn: () => api.get<EvidenceSummary[]>(`/cases/${selected}/evidence`),
    enabled: !!selected,
  });
  const current = cases.data?.find((c) => c.id === selected);

  return (
    <div className="grid gap-6 lg:grid-cols-[280px_1fr]">
      <aside className="flex flex-col gap-4">
        <Card>
          <CardHeader>
            <CardTitle>Cases</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-1 p-2">
            <ErrorNote error={cases.error} />
            {cases.data?.length === 0 && <p className="p-2 text-sm text-muted-foreground">No cases yet.</p>}
            {cases.data?.map((c) => (
              <button
                key={c.id}
                onClick={() => setSelected(c.id)}
                className={`cursor-pointer rounded-md px-3 py-2 text-left text-sm ${c.id === selected ? "bg-muted font-medium" : "hover:bg-muted/60"}`}
              >
                <div className="truncate">{c.title}</div>
                <div className="text-xs text-muted-foreground">{c.status} · {fmtDate(c.created_at)}</div>
              </button>
            ))}
          </CardContent>
        </Card>
        {isInvestigator && (
          <Card>
            <CardContent>
              <CreateCase onCreated={(c) => setSelected(c.id)} />
            </CardContent>
          </Card>
        )}
      </aside>

      <section className="flex min-w-0 flex-col gap-6">
        {!current ? (
          <EmptyState>{isInvestigator ? "Create a case to start registering evidence." : "No cases available."}</EmptyState>
        ) : (
          <>
            <div>
              <h1 className="text-lg font-semibold">{current.title}</h1>
              {current.description && <p className="text-sm text-muted-foreground">{current.description}</p>}
            </div>
            {isInvestigator && (
              <Card>
                <CardHeader>
                  <CardTitle>Register evidence</CardTitle>
                  <CardDescription>Originals are stored immutably under a random UUID key; the client filename is never used as a path.</CardDescription>
                </CardHeader>
                <CardContent>
                  <Upload caseId={current.id} />
                </CardContent>
              </Card>
            )}
            <Card>
              <CardHeader>
                <CardTitle>Evidence vault</CardTitle>
              </CardHeader>
              <CardContent className="p-0">
                <ErrorNote error={evidence.error} />
                {evidence.data?.length === 0 ? (
                  <div className="p-4"><EmptyState>No evidence registered in this case.</EmptyState></div>
                ) : (
                  <Table>
                    <THead>
                      <TR>
                        <TH>File</TH>
                        <TH>SHA-256</TH>
                        <TH>Type</TH>
                        <TH>Size</TH>
                        <TH>C2PA</TH>
                        <TH>Registered</TH>
                      </TR>
                    </THead>
                    <TBody>
                      {evidence.data?.map((e) => (
                        <TR key={e.id}>
                          <TD className="max-w-56 truncate">
                            <Link className="text-primary hover:underline" to={`/evidence/${e.id}`}>{e.original_filename}</Link>
                          </TD>
                          <TD><HashText value={e.sha256_digest} n={8} /></TD>
                          <TD><Badge>{e.mime_type.replace("image/", "")}</Badge></TD>
                          <TD className="text-xs">{fmtBytes(e.file_size)}</TD>
                          <TD><C2PABadge status={e.c2pa_status} /></TD>
                          <TD className="text-xs text-muted-foreground">{fmtDate(e.created_at)}</TD>
                        </TR>
                      ))}
                    </TBody>
                  </Table>
                )}
              </CardContent>
            </Card>
          </>
        )}
      </section>
    </div>
  );
}
