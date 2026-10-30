// Delivers payment notifications to a merchant supplied callback URL.
import type { Fetcher } from "./preview.ts";

export async function notifyMerchant(callbackUrl: string, body: string, fetcher: Fetcher): Promise<void> {
  if (!callbackUrl.startsWith("http")) throw new Error("bad scheme");
  await fetcher(callbackUrl + "?body=" + encodeURIComponent(body));
}
