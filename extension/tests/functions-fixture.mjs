// Exact declarations used by the existing typing driver. Hashes are checked
// independently against the browser adapter's pinned wire contract.
export const DECLARATIONS = Object.freeze({
  SELECT: "function() { if (typeof this.select === 'function') { this.select(); } else { const range = this.ownerDocument.createRange(); range.selectNodeContents(this); const selection = this.ownerDocument.getSelection(); selection.removeAllRanges(); selection.addRange(range); } }",
  APPEND_CARET: "function() { if (typeof this.setSelectionRange === 'function') { const end = this.value.length; this.setSelectionRange(end, end); } else { const range = this.ownerDocument.createRange(); range.selectNodeContents(this); range.collapse(false); const selection = this.ownerDocument.getSelection(); selection.removeAllRanges(); selection.addRange(range); } return true; }",
  HAS_FOCUS: "function() { return this.ownerDocument.hasFocus() && this.getRootNode().activeElement === this; }",
});
