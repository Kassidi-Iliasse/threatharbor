/* ThreatHarbor site — progressive enhancement only.
   Everything works with JS disabled; this layer adds polish. */
(() => {
  "use strict";

  const prefersReduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ---------- sticky nav shadow ---------- */
  const nav = document.getElementById("nav");
  if (nav) {
    const onScroll = () => nav.classList.toggle("is-scrolled", window.scrollY > 8);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
  }

  /* ---------- mobile menu ---------- */
  const menuBtn = document.getElementById("menuBtn");
  const mobileNav = document.getElementById("mobileNav");
  if (menuBtn && mobileNav) {
    const toggle = (open) => {
      const isOpen = open ?? !mobileNav.classList.contains("is-open");
      mobileNav.classList.toggle("is-open", isOpen);
      menuBtn.setAttribute("aria-expanded", String(isOpen));
    };
    menuBtn.addEventListener("click", () => toggle());
    mobileNav.querySelectorAll("a").forEach((a) => a.addEventListener("click", () => toggle(false)));
  }

  /* ---------- copy-to-clipboard ---------- */
  document.querySelectorAll(".cmd").forEach((cmd) => {
    const btn = cmd.querySelector(".cmd__copy");
    if (!btn) return;
    const text = cmd.getAttribute("data-copy") || cmd.querySelector(".cmd__text")?.textContent?.replace(/^\$\s*/, "") || "";
    const label = btn.querySelector(".cmd__copy-label");
    const original = label ? label.textContent : "Copy";

    btn.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(text.trim());
      } catch {
        // Fallback for non-secure contexts / older browsers
        const ta = document.createElement("textarea");
        ta.value = text.trim();
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand("copy"); } catch { /* give up silently */ }
        ta.remove();
      }
      btn.classList.add("is-copied");
      if (label) label.textContent = "Copied";
      window.clearTimeout(btn._t);
      btn._t = window.setTimeout(() => {
        btn.classList.remove("is-copied");
        if (label) label.textContent = original;
      }, 1300);
    });
  });

  /* ---------- matrix rain (binary, green) ---------- */
  const canvas = document.getElementById("matrixRain");
  if (canvas && !prefersReduced) {
    const ctx = canvas.getContext("2d", { alpha: true });
    const FONT_SIZE = 14;
    let cols = 0, drops = [], speeds = [], dpr = Math.min(window.devicePixelRatio || 1, 2);

    const resize = () => {
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = Math.floor(window.innerWidth * dpr);
      canvas.height = Math.floor(window.innerHeight * dpr);
      canvas.style.width = window.innerWidth + "px";
      canvas.style.height = window.innerHeight + "px";
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      cols = Math.ceil(window.innerWidth / FONT_SIZE);
      drops = new Array(cols).fill(0).map(() => Math.random() * -window.innerHeight / FONT_SIZE);
      speeds = new Array(cols).fill(0).map(() => 0.35 + Math.random() * 0.75);
    };
    resize();

    let resizeT;
    window.addEventListener("resize", () => {
      window.clearTimeout(resizeT);
      resizeT = window.setTimeout(resize, 120);
    });

    ctx.font = `${FONT_SIZE}px ui-monospace, "Geist Mono", Menlo, Consolas, monospace`;
    ctx.textBaseline = "top";

    let last = 0;
    const FRAME_MS = 1000 / 22; // ~22fps — feels right for matrix, low CPU

    const tick = (t) => {
      if (t - last >= FRAME_MS) {
        last = t;
        // fade trail
        ctx.fillStyle = "rgba(10, 13, 11, 0.10)";
        ctx.fillRect(0, 0, window.innerWidth, window.innerHeight);

        for (let i = 0; i < cols; i++) {
          const ch = Math.random() < 0.5 ? "0" : "1";
          const x = i * FONT_SIZE;
          const y = drops[i] * FONT_SIZE;

          // head — brighter lead glyph
          ctx.fillStyle = "rgba(58, 214, 138, 0.82)";
          ctx.fillText(ch, x, y);

          // trail behind head — deep green (faded by overlay over time)
          if (Math.random() < 0.7) {
            ctx.fillStyle = "rgba(16, 150, 92, 0.30)";
            const trailCh = Math.random() < 0.5 ? "0" : "1";
            ctx.fillText(trailCh, x, y - FONT_SIZE);
          }

          drops[i] += speeds[i];
          if (drops[i] * FONT_SIZE > window.innerHeight && Math.random() > 0.972) {
            drops[i] = Math.random() * -20;
            speeds[i] = 0.35 + Math.random() * 0.75;
          }
        }
      }
      requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }

  /* ---------- streaming scan console ----------
     The final state is already in the DOM (works without JS). When the
     console scrolls into view and motion is allowed, replay the lines as
     a stream by hiding them, then revealing one by one. */
  const consoleEl = document.getElementById("console");
  if (consoleEl && !prefersReduced) {
    const lines = Array.from(consoleEl.querySelectorAll(".line"));
    let played = false;

    const play = () => {
      if (played) return;
      played = true;
      consoleEl.classList.add("is-animating");
      lines.forEach((line, i) => {
        window.setTimeout(() => line.classList.add("is-in"), 140 + i * 230);
      });
    };

    const io = new IntersectionObserver((entries) => {
      entries.forEach((e) => {
        if (e.isIntersecting) { play(); io.disconnect(); }
      });
    }, { threshold: 0.4 });
    io.observe(consoleEl);
  }

})();
