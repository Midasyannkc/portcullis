const MAP: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
export const escapeHtml = (s: string): string => s.replace(/[&<>"']/g, (c) => MAP[c]);

export function renderNote(note: string): string {
  return `<p class="note">${escapeHtml(note)}</p>`;
}
