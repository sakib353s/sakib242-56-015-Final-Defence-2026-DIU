"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiFetch, get } from "@/lib/api";
import { bytes, fmtTs, humanStatus, statusTone, trunc } from "@/lib/format";
import { useStepUp } from "@/components/stepup";
import { useToast } from "@/components/toast";
import { Chip, EmptyRows, ErrBanner, Field, KV, LoaderRows, Modal, Panel } from "@/components/ui";
import type { DocDetail, DocIngest, DocRow } from "@/lib/types";

/* What the crawler concluded about each URL it found. */
const VERDICT_LABEL: Record<string, string> = {
  match: "Identical copy",
  variant_match: "Same content, re-encoded",
  no_match: "Different content",
  skipped_robots: "Skipped (robots.txt)",
  error: "Could not check",
  pending: "Not checked yet",
};

export default function DocumentPage() {
  const qc = useQueryClient();
  const toast = useToast();
  const { requestTotp } = useStepUp();
  const fileRef = useRef<HTMLInputElement>(null);

  const [attested, setAttested] = useState(false);
  const [over, setOver] = useState(false);
  const [uploadErr, setUploadErr] = useState<unknown>(null);
  const [ingested, setIngested] = useState<DocIngest | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [crawlOpen, setCrawlOpen] = useState(false);
  const [seeds, setSeeds] = useState("");
  const [crawlBusy, setCrawlBusy] = useState(false);
  const [evidenceErr, setEvidenceErr] = useState<unknown>(null);

  const docs = useQuery({ queryKey: ["document", "list"], queryFn: () => get<{ documents: DocRow[] }>("/document") });

  const detail = useQuery({
    queryKey: ["document", selected],
    queryFn: () => get<DocDetail>(`/document/${selected}`),
    enabled: !!selected,
  });

  useEffect(() => {
    if (!selected && (docs.data?.documents ?? []).length) setSelected(docs.data!.documents[0].id);
  }, [selected, docs.data]);

  const upload = useCallback(
    async (f: File) => {
      setUploadErr(null);
      const form = new FormData();
      form.append("file", f);
      form.append("ownership_confirmed", String(attested));
      try {
        const res = await apiFetch<DocIngest>("/document/upload", { method: "POST", form });
        setIngested(res);
        setSelected(res.id);
        toast.push({ tone: "ok", title: "Document analyzed", text: `${trunc(res.id, 10)} · ${res.watermark_id}` });
        qc.invalidateQueries({ queryKey: ["document"] });
      } catch (e) {
        setUploadErr(e);
      }
    },
    [attested, qc, toast],
  );

  async function triggerCrawl() {
    setCrawlBusy(true);
    const urls = seeds
      .split(/\n+/)
      .map((s) => s.trim())
      .filter(Boolean);
    const code = await requestTotp(`document: crawl ${urls.length} public seed URLs for ${trunc(selected ?? "", 8)}`);
    setCrawlBusy(false);
    if (!code || !selected) {
      setCrawlOpen(false);
      return;
    }
    try {
      const r = await apiFetch<{ status: string; doc_id: string }>(`/document/${selected}/crawl`, {
        method: "POST",
        body: { seed_urls: urls },
        totp: code,
      });
      toast.push({ tone: "ok", title: r.status, text: `${urls.length} seed URLs queued for crawling` });
      setCrawlOpen(false);
      detail.refetch();
    } catch (e) {
      toast.push({ tone: "fail", title: "crawl refused", text: String((e as Error).message) });
    }
    setCrawlOpen(false);
  }

  async function evidencePack() {
    if (!selected) return;
    setEvidenceErr(null);
    const code = await requestTotp("document: download the evidence pack");
    if (!code) return;
    try {
      const r = await apiFetch<{ download: string }>(`/document/${selected}/evidence`, { method: "POST", totp: code });
      window.open(r.download, "_blank");
      toast.push({ tone: "ok", title: "Evidence pack", text: "Signed link issued, valid for 300 seconds" });
    } catch (e) {
      setEvidenceErr(e);
    }
  }

  const totalCopies = (detail.data?.copies ?? []).filter((c) => c.verdict === "match" || c.verdict === "variant_match").length;

  return (
    <>
      <div className="span-12">
        <Panel title="Analyze a document">
          <div className="form-row" style={{ alignItems: "center" }}>
            <div
              className={`dropzone${over ? " over" : ""}`}
              role="button"
              tabIndex={0}
              aria-label="upload document"
              style={{ flex: "1 1 420px" }}
              onClick={() => fileRef.current?.click()}
              onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && fileRef.current?.click()}
              onDragOver={(e) => {
                e.preventDefault();
                setOver(true);
              }}
              onDragLeave={() => setOver(false)}
              onDrop={(e) => {
                e.preventDefault();
                setOver(false);
                const f = e.dataTransfer.files?.[0];
                if (f) void upload(f);
              }}
            >
              Drop a PNG, JPG, or PDF file here, or click to select one
              <br />
              <span className="page-note">Maximum file size is 50 MiB. An LSB or XMP watermark is embedded, and SHA-256 and MD5 checksums are recorded.</span>
            </div>
            <label className="checkline" style={{ flex: "1 1 260px", paddingTop: 4 }}>
              <input type="checkbox" checked={attested} onChange={(e) => setAttested(e.target.checked)} />
              I confirm that I own this document or am mandated to handle it. The server requires this confirmation before accepting an upload.
            </label>
          </div>
          <input
            ref={fileRef}
            type="file"
            accept=".png,.jpg,.jpeg,.pdf"
            style={{ display: "none" }}
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) void upload(f);
              e.target.value = "";
            }}
          />
          {uploadErr ? <ErrBanner error={uploadErr} /> : null}
          {ingested ? (
            <div className="lockline" style={{ marginTop: 10 }}>
              Latest ingest: <b className="cell-id">{trunc(ingested.id, 14)}</b> ·{" "}
              <span style={{ color: "var(--ok)" }}>{trunc(ingested.sha256, 24)}</span> · watermark{" "}
              <Chip tone="info" label={ingested.watermark_id} /> · {bytes(ingested.size)} · {ingested.mime}
            </div>
          ) : null}
        </Panel>
      </div>

      <div className="span-12">
        <div className="wb">
          <div>
            <div className="panel-title" style={{ marginBottom: 8 }}>Register · {(docs.data?.documents ?? []).length}</div>
            {docs.isPending ? (
              <LoaderRows lines={["Loading the register"]} />
            ) : docs.error ? (
              <ErrBanner error={docs.error} onRetry={() => docs.refetch()} />
            ) : !docs.data!.documents.length ? (
              <EmptyRows what="No documents registered yet. Upload a file above." />
            ) : (
              <div className="wb-list" role="listbox" aria-label="Registered documents">
                {docs.data!.documents.map((d) => (
                  <button
                    key={d.id}
                    type="button"
                    role="option"
                    aria-selected={selected === d.id}
                    className={`wb-item${selected === d.id ? " on" : ""}`}
                    onClick={() => setSelected(d.id)}
                  >
                    <span className="wb-dot ok" aria-hidden />
                    <span className="wb-main">
                      <span className="wb-target">{d.filename}</span>
                      <span className="wb-meta">{trunc(d.sha256, 14)} · {bytes(d.size)}</span>
                    </span>
                    <span className="wb-side">
                      <Chip tone="info" label={d.watermark_id} />
                    </span>
                  </button>
                ))}
              </div>
            )}
          </div>

          <Panel
            title="Document details and copies"
            tight
            actions={
              selected ? (
                <div style={{ display: "flex", gap: 6 }}>
                  <button type="button" className="btn small warn" onClick={() => setCrawlOpen(true)}>
                    Trigger crawl
                  </button>
                  <button type="button" className="btn small primary" onClick={evidencePack}>
                    Evidence pack
                  </button>
                </div>
              ) : null
            }
          >
            {!selected ? (
              <div style={{ padding: 12 }}>
                <EmptyRows what="Select a document to view its digest and copy records" />
              </div>
            ) : detail.isPending ? (
              <LoaderRows lines={["Loading the document", "Reading checksums and copy records"]} />
            ) : detail.error ? (
              <div style={{ padding: 12 }}>
                <ErrBanner error={detail.error} onRetry={() => detail.refetch()} />
              </div>
            ) : (
              <div style={{ padding: 12 }}>
                <KV
                  rows={[
                    ["File", detail.data.document.filename],
                    ["SHA-256", <span key="s" style={{ color: "var(--ok)", wordBreak: "break-all", fontSize: 11 }}>{detail.data.document.sha256}</span>],
                    ["MD5", detail.data.document.md5],
                    ["Watermark", <Chip key="w" tone="info" label={detail.data.document.watermark_id} />],
                    ["Registered", `${fmtTs(detail.data.document.created_at)} · ${bytes(detail.data.document.size)} · ${detail.data.document.mime}`],
                    ["Copies in the wild", `${totalCopies} confirmed of ${detail.data.copies.length} URLs checked`],
                  ]}
                />
                {evidenceErr ? <ErrBanner error={evidenceErr} /> : null}
                <div style={{ marginTop: 12 }}>
                  <div className="page-note" style={{ marginBottom: 4 }}>Copies found by the public crawl, which respects robots.txt</div>
                  {!detail.data.copies.length ? (
                    <EmptyRows what="No copies located yet. Trigger a crawl to search." />
                  ) : (
                    <table className="dtable">
                      <thead>
                        <tr>
                          <th>URL</th>
                          <th>Verdict</th>
                          <th>Found</th>
                        </tr>
                      </thead>
                      <tbody>
                        {detail.data.copies.map((c, i) => (
                          <tr key={i}>
                            <td style={{ maxWidth: 340, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{c.url}</td>
                            <td>
                              <Chip tone={statusTone(c.verdict) === "fail" ? "fail" : c.verdict === "match" ? "warn" : "info"} label={VERDICT_LABEL[c.verdict] ?? humanStatus(c.verdict)} />
                            </td>
                            <td className="cell-id">{fmtTs(c.found_at)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              </div>
            )}
          </Panel>
        </div>
      </div>

      {crawlOpen ? (
        <Modal
          title="Crawl public seed URLs"
          onClose={() => setCrawlOpen(false)}
          footer={
            <>
              <button type="button" className="btn" onClick={() => setCrawlOpen(false)}>
                Cancel
              </button>
              <button type="button" className="btn warn" disabled={!seeds.trim() || crawlBusy} onClick={triggerCrawl}>
                Queue crawl
              </button>
            </>
          }
        >
          <Field label="Seed URLs (one per line, up to 10)" hint="Public HTTP(S) addresses only. robots.txt is honored, and every copy is checked against the watermark.">
            <textarea value={seeds} onChange={(e) => setSeeds(e.target.value)} placeholder={"https://repo.example/thesis\nhttps://mirror.example/docs"} />
          </Field>
        </Modal>
      ) : null}
    </>
  );
}
