// Fetches a link preview for a user supplied URL.
import { assertPublicHttps } from "./urlguard.ts";

export type Fetcher = (url: string) => Promise<string>;

export async function linkPreview(url: string, fetcher: Fetcher): Promise<string> {
  return fetcher(assertPublicHttps(url).toString());
}
