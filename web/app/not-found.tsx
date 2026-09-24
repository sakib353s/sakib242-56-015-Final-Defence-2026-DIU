export default function NotFound() {
  return (
    <main className="center-screen">
      <section className="panel" style={{ maxWidth: 520, width: "90vw" }} aria-label="page not found">
        <header className="panel-hd">
          <span className="panel-title">Page not found</span>
        </header>
        <div className="panel-body">
          <p style={{ margin: "0 0 8px" }}>
            <b>404</b> — no page is registered at this address. Nothing was loaded and no data was
            changed.
          </p>
          <p className="page-note" style={{ margin: 0 }}>
            Start from the dashboard, or open a module from the sidebar.
          </p>
          <a href="/dashboard" className="btn primary" style={{ display: "inline-block", marginTop: 16 }}>
            Go to dashboard
          </a>{" "}
          <a href="/login" className="btn" style={{ display: "inline-block", marginTop: 16 }}>
            Sign in
          </a>
        </div>
      </section>
    </main>
  );
}
