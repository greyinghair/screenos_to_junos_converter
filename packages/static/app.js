"use strict";

/*
 * Presentation only. Every conversion, validation and diagnostic shown on the
 * page is produced by the server; this file adds convenience behaviour that
 * the interface stays fully usable without.
 */

(function () {
  const downloadButton = document.querySelector("#download-preview");
  const output = document.querySelector("#converted_output");

  if (downloadButton && output) {
    downloadButton.addEventListener("click", () => {
      const blob = new Blob([output.value], { type: "text/plain;charset=utf-8" });
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = downloadButton.dataset.downloadName || "converted_screenos.txt";
      link.click();
      URL.revokeObjectURL(link.href);
    });
  }

  const form = document.querySelector("[data-conversion-form]");
  if (!form) {
    return;
  }

  const workspace = form.querySelector("[data-workspace]");
  const convertButtons = Array.from(form.querySelectorAll("[data-action-convert]"));
  const blockedHint = form.querySelector("[data-conversion-blocked]");
  const mappedCount = form.querySelector("[data-count-mapped]");
  const invalidCount = form.querySelector("[data-count-invalid]");
  const rows = workspace
    ? Array.from(workspace.querySelectorAll("[data-mapping-row]"))
    : [];
  // The server already rejected these mappings, so conversion stays disabled
  // until the operator changes one of them.
  let serverBlocked = Boolean(workspace && workspace.dataset.blocksConversion);

  function syncVlanRow(row) {
    const mode = row.querySelector("[data-vlan-mode]");
    const vlanId = row.querySelector("[data-vlan-id]");
    if (!mode || !vlanId) {
      return;
    }
    // Only the requirement changes: the field keeps its value so a submitted
    // choice survives a round trip through the server.
    vlanId.required = mode.value === "tagged";
  }

  function refresh() {
    rows.forEach(syncVlanRow);
    if (mappedCount) {
      const mapped = rows.filter((row) => {
        const destination = row.querySelector('input[type="text"]');
        return destination && destination.value.trim() !== "";
      }).length;
      mappedCount.textContent = String(mapped);
    }
    const invalid = rows.filter((row) => row.querySelector(":invalid")).length;
    if (invalidCount && !serverBlocked) {
      invalidCount.textContent = String(invalid);
    }
    const blocked = serverBlocked || invalid > 0;
    convertButtons.forEach((button) => {
      button.disabled = blocked;
    });
    if (blockedHint) {
      blockedHint.hidden = !blocked;
    }
  }

  form.addEventListener("input", (event) => {
    if (event.target.closest("[data-mapping-row]")) {
      serverBlocked = false;
    }
    refresh();
  });
  form.addEventListener("change", refresh);

  const working = document.querySelector("[data-flow-working]");
  if (working) {
    form.addEventListener("submit", () => {
      working.hidden = false;
    });
    document.addEventListener("visibilitychange", () => {
      document.documentElement.toggleAttribute(
        "data-hidden-tab",
        document.visibilityState === "hidden"
      );
    });
  }

  refresh();
})();
