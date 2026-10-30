// Fetches a link preview for a user supplied URL.
export type Fetcher = (url: string) => Promise<string>;

export async function linkPreview(url: string, fetcher: Fetcher): Promise<string> {
  if (!url.startsWith("http")) throw new Error("bad scheme");
  return fetcher(url);
}
