// Static local UI only. Runtime and provider text is inserted with textContent.
export const layout = `
<a class="skip-link" href="#main">Skip to node status</a>
<header class="site-header">
  <div class="header-inner">
    <span class="brand">
      <svg class="brand-mark" viewBox="0 0 64 64" aria-hidden="true"><g stroke="currentColor" stroke-width="4.5" stroke-linecap="round"><path d="M12 32 54 10M12 32 54 54" opacity=".4"/><path d="M12 32 54 21M12 32 54 43" opacity=".65"/></g><path d="M12 32h42" stroke="#f0382b" stroke-width="7" stroke-linecap="round"/><circle cx="12" cy="32" r="7" fill="#f0382b"/></svg>
      <span class="brand-name">SCARLETT</span><span class="brand-tag">Node</span>
    </span>
    <div class="actions"><button id="dashboard" class="quiet header-link">Open dashboard ↗</button><button id="quit" class="quiet header-link">Quit Scarlett</button></div>
  </div>
</header>
<main id="main" tabindex="-1">
  <p id="notice" role="status" aria-live="polite" hidden></p>
  <section class="node-overview" aria-labelledby="status">
    <div class="overview-copy">
      <p class="eyebrow">THIS DEVICE</p>
      <div class="status-line"><span id="status-dot" class="status-dot" aria-hidden="true"></span><h1 id="status">Checking local runtime</h1></div>
      <p id="runtime-note">Connecting to the installed node</p>
      <p id="x-proofs" class="proof-chip" hidden></p>
    </div>
    <div class="node-controls"><div class="actions"><button id="start">Start node</button><button id="pause">Pause</button><button id="resume">Resume</button><button id="stop" class="quiet">Stop</button></div><p id="work" class="muted"></p></div>
  </section>
  <section id="relay-banner" class="relay-banner" aria-labelledby="relay-heading" hidden><div><h2 id="relay-heading">Keyed relay is paused on this node</h2><p id="relay-detail" tabindex="-1"></p></div><button id="relay-resume" type="button">Resume relay</button></section>
  <div class="metrics" aria-label="Local node activity">
    <div class="metric"><span class="metric-label">Saved accounts</span><strong id="metric-accounts">—</strong><span class="metric-note">On this device</span></div>
    <div class="metric"><span class="metric-label">Available X slots</span><strong id="metric-capacity">—</strong><span class="metric-note">Ready for new work</span></div>
    <div class="metric"><span class="metric-label">Jobs in flight</span><strong id="metric-jobs">—</strong><span class="metric-note">Currently running</span></div>
    <div class="metric"><span class="metric-label">Awaiting reconciliation</span><strong id="metric-pending">—</strong><span class="metric-note">Pending confirmation</span></div>
  </div>
  <section id="pair-section" class="panel pairing" aria-labelledby="pair-heading">
    <div class="section-head"><div><h2 id="pair-heading">Pair with Scarlett</h2><p class="section-description">Link this device to your network account</p></div><button id="setup" class="quiet">Open setup ↗</button></div>
    <p>Sign in, redeem your invite and bind your wallet in your browser. Then paste the one-time pairing code here</p>
    <form id="pair-form" class="inline-form"><label>Pairing code<input id="pair-code" type="password" autocomplete="off" spellcheck="false" maxlength="64" required></label><button type="submit">Pair node</button></form>
  </section>
  <section class="panel accounts-panel" aria-labelledby="accounts-heading">
    <div class="section-head"><div><h2 id="accounts-heading" tabindex="-1">Connected accounts</h2><p class="section-description">Credentials stay on this device</p></div><span id="account-note" class="muted"></span></div>
    <div id="accounts"></div>
    <p id="accounts-empty" class="empty-state" hidden>Connect an account to start serving work</p>
    <details id="connect-accounts" class="connect-details">
      <summary aria-label="Add account">Add account</summary>
      <div class="account-forms">
        <details id="x-login-panel" class="connection">
          <summary aria-label="Sign in to X"><span class="provider-mark" aria-hidden="true">X</span><span>Sign in to X<span class="method-note">Use the browser on this device</span></span></summary>
          <div class="connection-body x-browser-login">
            <form id="x-login-form">
              <p>Sign in through the browser on this device, then enter any verification code here. Passwords and codes are used only for this login</p>
              <label>Local account ID for X login<input id="x-login-id" autocomplete="off" pattern="[a-z0-9_-]{1,32}" maxlength="32" required></label><input id="x-login-capacity" type="hidden" value="1">
              <label class="check"><input id="x-login-reconnect" type="checkbox">Replace the session for an existing local account</label>
              <label>X username<input id="x-login-username" autocomplete="username" maxlength="64" required></label>
              <label>Password<input id="x-login-password" type="password" autocomplete="current-password" maxlength="1024" required></label>
              <div class="actions"><button id="x-login-start" type="submit">Sign in to X</button><button id="x-login-cancel" type="button" class="quiet" hidden>Cancel X login</button></div><p id="x-login-note" role="status" class="muted"></p>
            </form>
            <form id="x-challenge-form" hidden><h3>Verify your X login</h3><label>Verification code<input id="x-login-code" type="password" autocomplete="one-time-code" maxlength="128" required></label><button id="x-login-continue" type="submit">Continue login</button></form>
          </div>
        </details>
        <details id="codex-panel" class="connection">
          <summary aria-label="Connect Codex"><span class="provider-mark" aria-hidden="true">C</span><span>Connect Codex<span class="method-note">Sign in with your ChatGPT account</span></span></summary>
          <form id="codex-form" class="connection-body"><p>Scarlett creates a private profile on this device for each account</p><div class="actions"><button type="submit">Connect Codex</button><button id="cancel-login" type="button" class="quiet" hidden>Cancel login</button></div><p id="codex-note" class="muted"></p></form>
        </details>
        <details id="x-import-panel" class="connection">
          <summary aria-label="Import an X session"><span class="provider-mark" aria-hidden="true">X</span><span>Import an X session<span class="method-note">Use an existing browser profile or cookies</span></span></summary>
          <form id="x-form">
            <div id="x-reimport" class="reimport" hidden><strong id="x-reimport-title"></strong><p>Choose a browser profile signed in to this X account, or paste its two cookies. The account keeps its ID and job limit.</p><button id="x-reimport-cancel" type="button" class="quiet">Cancel re-import</button></div>
            <label>Local X account ID<input id="x-id" autocomplete="off" pattern="[a-z0-9_-]{1,32}" maxlength="32" placeholder="personal-x" required></label><input id="x-capacity" type="hidden" value="1">
            <label>Browser profile<select id="x-profile" disabled><option value="">Loading browser profiles</option></select></label>
            <label class="check"><input id="x-consent" type="checkbox">Import only X session cookies from this profile</label><button id="x-import" type="button" disabled>Import X account</button>
            <p class="muted">Close the selected browser before importing. The OS may ask for permission; protected stores can use cookie paste</p>
            <div class="form-divider"><span>Or paste session cookies</span></div>
            <label>auth_token<input id="x-token" type="password" autocomplete="off" spellcheck="false" maxlength="64" required></label>
            <label>ct0<input id="x-ct0" type="password" autocomplete="off" spellcheck="false" maxlength="160" required></label><button type="submit">Connect X</button><p id="x-import-note" class="muted"></p>
          </form>
        </details>
      </div>
      <p class="muted setup-note">Each X account runs one job at a time. Set the total across accounts in Device settings</p>
    </details>
  </section>
  <div class="settings-stack">
    <section aria-labelledby="local-api-heading">
      <details id="local-api-panel" class="panel disclosure">
        <summary aria-label="Local model API"><span><h2 id="local-api-heading">Local model API</h2><span class="section-description">Use Codex and Claude from your tools</span></span><span id="api-summary" class="summary-state">Checking</span></summary>
        <div class="disclosure-body">
          <p>Connect your tools using an OpenAI-compatible API. Stop network jobs before starting the local API</p>
          <p id="api-status" class="muted"></p>
          <div class="form-grid"><label>Local port<input id="api-port" type="number" min="1024" max="65535" value="8088"></label><label>Claude billing<select id="claude-mode"><option value="subscription">Claude subscription</option><option value="api_key">Anthropic API key · separate usage billing</option></select></label></div>
          <div class="subsection"><h3>Connect Claude</h3><p>Your browser handles subscription login. Claude keeps this app’s credentials on this device</p><p id="claude-status" class="muted"></p><div class="actions"><button id="claude-connect" type="button">Connect Claude subscription</button><button id="claude-cancel" type="button" class="quiet" hidden>Cancel Claude login</button><button id="claude-disconnect" type="button" class="quiet">Disconnect Claude</button></div></div>
          <label id="claude-key-label" hidden>Anthropic API key<input id="claude-key" type="password" autocomplete="off" spellcheck="false" maxlength="512"></label><p class="muted">Subscription mode uses your connected claude.ai account. API key mode bills Anthropic API usage separately; the key is cleared when the service stops. Stop the local API before changing billing mode</p>
          <div class="actions"><button id="api-start" type="button">Start local API</button><button id="api-stop" type="button" class="quiet">Stop local API</button><button id="api-show-key" type="button" class="quiet">Show local API key</button><button id="api-hide-key" type="button" class="quiet" hidden>Hide key</button></div><label id="api-key-label" hidden>Local API key<input id="api-key" type="password" readonly autocomplete="off" spellcheck="false"></label><p class="muted">Use the address above as your base URL and this private key as the bearer token. Restart the local API after adding Codex accounts</p>
        </div>
      </details>
    </section>
    <section aria-labelledby="preferences-heading">
      <details id="preferences-panel" class="panel disclosure">
        <summary aria-label="Device settings"><span><h2 id="preferences-heading">Device settings</h2><span class="section-description">Job limits and startup preferences</span></span></summary>
        <div class="disclosure-body">
          <form id="preferences-form"><div class="form-grid"><label>Maximum simultaneous X jobs<input id="x-concurrency" type="number" min="1" max="8" value="2" required></label><label>Saved local API port<input id="saved-api-port" type="number" min="1024" max="65535" required></label></div><p class="muted">Each verified X account runs one job at a time. The total is limited by ready accounts and this setting. Changes apply after you stop and start the node; accepted jobs finish before it stops</p><label class="check"><input id="background" type="checkbox">Keep running when the window closes</label><p class="muted">When off, closing the window drains accepted jobs and quits Scarlett. When on, use the menu bar or tray to reopen or quit</p><button type="submit">Save device preferences</button></form>
          <div class="subsection"><label class="check"><input id="autostart" type="checkbox" disabled>Open Scarlett when I log in</label><p class="muted">Opening Scarlett does not start network jobs or the local API. You choose when to start them</p></div>
        </div>
      </details>
    </section>
    <section aria-labelledby="diagnostics-heading">
      <details id="diagnostics-panel" class="panel disclosure">
        <summary aria-label="Local request measurements"><span><h2 id="diagnostics-heading" tabindex="-1">Local request measurements</h2><span class="section-description">Recent timings and attempt history</span></span></summary>
        <div class="disclosure-body"><p id="diagnostics-note" class="muted">Checking local measurements</p><p id="diagnostics-capacity" class="muted"></p><details class="measurement-help"><summary>How to read these measurements</summary><p class="muted">Recent attempts stay on this device for 24 hours, up to 200 attempts. Times use local monotonic clocks. Helper clocks start separately for each page; spans can overlap. Handshake milestones can include protocol setup and verifier admission, and first-response timing includes transport through the proof path. Unclassified time means it has not been assigned to a measured phase</p></details><div id="diagnostics-history"></div></div>
      </details>
    </section>
  </div>
  <footer><span>Suppliers earn points only · local status does not confirm an award</span><button id="settings" class="quiet header-link">Manage node access ↗</button></footer>
</main>
<dialog id="remove-account-dialog" aria-labelledby="remove-account-heading" aria-describedby="remove-account-detail"><h2 id="remove-account-heading"></h2><p id="remove-account-detail">This account will stop receiving new work when the node picks up the change. Accepted jobs keep their original account and finish. Saved credentials remain on this device.</p><div class="actions"><button id="remove-account-cancel" type="button" class="secondary">Keep account</button><button id="remove-account-confirm" type="button">Remove account</button></div></dialog>`;

// Reveal controls before a recovery flow moves keyboard focus inside them.
export function revealControl(element: HTMLElement): void {
  for (let parent = element.parentElement; parent; parent = parent.parentElement) {
    if (parent instanceof HTMLDetailsElement) parent.open = true;
  }
}
