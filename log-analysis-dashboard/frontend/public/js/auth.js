(function () {
  "use strict";

  const API = "http://localhost:4000";
  const LOGIN_PAGE = "login.html";
  const LANDING_PAGE = "landing.html";
  const REFRESH_INTERVAL_MS = 12 * 60 * 1000;

  /* ── Token helpers ──────────────────────────────────────────────────────── */
  function getToken() {
    return sessionStorage.getItem("accessToken");
  }

  function getUser() {
    try {
      return JSON.parse(sessionStorage.getItem("user")) || null;
    } catch {
      return null;
    }
  }

  function setToken(token) {
    sessionStorage.setItem("accessToken", token);
  }

  function clearSession() {
    sessionStorage.removeItem("accessToken");
    sessionStorage.removeItem("user");
  }

  /* ── Redirect if not authenticated ─────────────────────────────────────── */
  function guardRoute() {
    if (!getToken()) {
      window.location.replace(LOGIN_PAGE);
      return false;
    }
    return true;
  }

  /* ── Token refresh ──────────────────────────────────────────────────────── */
  async function refreshAccessToken() {
    try {
      const res = await fetch(`${API}/api/auth/refresh`, {
        method: "POST",
        credentials: "include", // sends httpOnly refresh token cookie
      });

      if (!res.ok) {
        // Refresh failed — force re-login
        clearSession();
        window.location.replace(LOGIN_PAGE);
        return null;
      }

      const data = await res.json();
      setToken(data.accessToken);
      return data.accessToken;
    } catch {
      return null;
    }
  }

  window.authFetch = async function (url, options = {}) {
    const token = getToken();
    const headers = {
      "Content-Type": "application/json",
      ...(options.headers || {}),
      Authorization: `Bearer ${token}`,
    };

    let res = await fetch(url, { ...options, headers, credentials: "include" });

    if (res.status === 401) {
      // Try refreshing
      const newToken = await refreshAccessToken();
      if (!newToken) return res; // Already redirected

      headers["Authorization"] = `Bearer ${newToken}`;
      res = await fetch(url, { ...options, headers, credentials: "include" });
    }

    if (res.status === 403) {
      clearSession();
      window.location.replace(LOGIN_PAGE);
    }

    return res;
  };

  /* ── Logout ─────────────────────────────────────────────────────────────── */
  window.logout = async function () {
    try {
      await window.authFetch(`${API}/api/auth/logout`, { method: "POST" });
    } finally {
      clearSession();
      window.location.replace(LANDING_PAGE);
    }
  };

  /* ── Render user info in header ─────────────────────────────────────────── */
  function renderUserBar() {
    const user = getUser();
    if (!user) return;

    const roleColors = {
      admin: {
        bg: "rgba(251,191,36,0.12)",
        color: "#fbbf24",
        border: "rgba(251,191,36,0.3)",
      },
      analyst: {
        bg: "rgba(0,212,255,0.10)",
        color: "#00d4ff",
        border: "rgba(0,212,255,0.3)",
      },
      viewer: {
        bg: "rgba(148,163,184,0.10)",
        color: "#94a3b8",
        border: "rgba(148,163,184,0.3)",
      },
    };

    const rc = roleColors[user.role] || roleColors.viewer;

    const bar = document.createElement("div");
    bar.id = "auth-user-bar";
    bar.style.cssText = `
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 0 6px;
      margin-right: 8px;
    `;

    bar.innerHTML = `
      <div style="
        display:flex;
        align-items:center;
        gap:8px;
        background:rgba(255,255,255,0.04);
        border:1px solid #1e3a5a;
        border-radius:8px;
        padding:6px 12px;
      ">
        <div style="
          width:28px;height:28px;
          border-radius:50%;
          background:linear-gradient(135deg,#00d4ff,#7c3aed);
          display:flex;align-items:center;justify-content:center;
          font-size:11px;font-weight:700;color:#050a14;
          flex-shrink:0;
        ">${user.username.slice(0, 2).toUpperCase()}</div>
        <div>
          <div style="font-size:13px;font-weight:700;line-height:1.2;color:#e2e8f0;">${user.username}</div>
          <div style="
            font-size:10px;font-weight:700;font-family:'Space Mono',monospace;
            color:${rc.color};letter-spacing:0.05em;text-transform:uppercase;
          ">${user.role}</div>
        </div>
      </div>
      <button
        onclick="logout()"
        title="Sign out"
        style="
          background:rgba(239,68,68,0.1);
          border:1px solid rgba(239,68,68,0.25);
          border-radius:8px;
          color:#f87171;
          font-size:12px;
          padding:8px 10px;
          cursor:pointer;
          transition:background 0.2s;
          font-family:inherit;
        "
        onmouseover="this.style.background='rgba(239,68,68,0.2)'"
        onmouseout="this.style.background='rgba(239,68,68,0.1)'"
      ><i class="fas fa-right-from-bracket"></i></button>
    `;

    // Insert into header-actions div
    const headerActions = document.querySelector(".header-actions");
    if (headerActions) {
      headerActions.insertBefore(bar, headerActions.firstChild);
    }
  }

  /* ── Role-based UI control ──────────────────────────────────────────────── */
  function applyRolePermissions() {
    const user = getUser();
    if (!user) return;

    // Hide admin-only elements for non-admins
    if (user.role !== "admin") {
      document.querySelectorAll("[data-role='admin']").forEach((el) => {
        el.style.display = "none";
      });
    }

    // Hide analyst+ elements for viewers
    if (user.role === "viewer") {
      document.querySelectorAll("[data-role='analyst']").forEach((el) => {
        el.style.display = "none";
      });
    }
  }

  /* ── Patch existing fetch calls (script.js uses fetch directly) ─────────── */
  function patchGlobalFetch() {
    const _fetch = window.fetch;
    window.fetch = async function (url, options = {}) {
      // Only patch calls to our API
      if (typeof url === "string" && url.startsWith(API)) {
        const token = getToken();
        if (token) {
          options.headers = {
            ...options.headers,
            Authorization: `Bearer ${token}`,
          };
          options.credentials = "include";
        }
      }
      return _fetch.call(this, url, options);
    };
  }

  /* ── Initialize ─────────────────────────────────────────────────────────── */
  function init() {
    if (!guardRoute()) return;

    // Patch fetch globally so existing script.js calls work without changes
    patchGlobalFetch();

    // Set up periodic token refresh
    setInterval(refreshAccessToken, REFRESH_INTERVAL_MS);

    // Render user info once DOM is ready
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", () => {
        renderUserBar();
        applyRolePermissions();
      });
    } else {
      renderUserBar();
      applyRolePermissions();
    }
  }

  init();
})();
