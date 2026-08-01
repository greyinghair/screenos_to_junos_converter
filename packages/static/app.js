"use strict";

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
