/*
 * Keyboard access to code blocks that scroll sideways (WCAG 2.1.1).
 *
 * A block wider than the column can only be scrolled with a pointer unless it can
 * take focus. Only a block that actually overflows gets a tab stop, a role and a
 * label; the check reruns when the block changes size, and on every page Material
 * swaps in with instant navigation (document$ emits after each swap, where
 * DOMContentLoaded fires only once).
 */
(function () {
  "use strict";

  var observer = window.ResizeObserver
    ? new window.ResizeObserver(function (entries) {
        entries.forEach(function (entry) {
          update(entry.target);
        });
      })
    : null;

  function update(code) {
    if (code.scrollWidth - code.clientWidth > 1) {
      code.setAttribute("tabindex", "0");
      code.setAttribute("role", "region");
      code.setAttribute("aria-label", "Code block");
    } else {
      ["tabindex", "role", "aria-label"].forEach(function (name) {
        code.removeAttribute(name);
      });
    }
  }

  function scan() {
    if (observer) observer.disconnect();
    document.querySelectorAll(".md-typeset pre > code").forEach(function (code) {
      update(code);
      if (observer) observer.observe(code);
    });
  }

  if (typeof document$ !== "undefined") {
    document$.subscribe(scan);
  } else if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", scan);
  } else {
    scan();
  }
})();
