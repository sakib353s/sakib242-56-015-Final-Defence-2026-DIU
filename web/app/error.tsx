"use client";

export default function GlobalError({ reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return (
    <main className="center-screen">
      <section className="panel" style={{ maxWidth: 520, width: "90vw" }} aria-label="unexpected error">
        <header className="panel-hd">
          <span className="panel-title" style={{ color: "var(--fail)" }}>
            Something went wrong
          </span>
        </header>
        <div className="panel-body">
          <p style={{ margin: "0 0 8px" }}>
            This page stopped rendering unexpectedly. Records already saved are unaffected — try
            again, and reload the page if the problem persists.
          </p>
          <button type="button" className="btn primary" style={{ marginTop: 16 }} onClick={reset}>
            Try again
          </button>{" "}
          <a href="/dashboard" className="btn" style={{ display: "inline-block", marginTop: 16, marginLeft: 8 }}>
            Back to dashboard
          </a>
        </div>
      </section>
    </main>
  );
}
