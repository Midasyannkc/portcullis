// Delivers payment notifications to a merchant supplied callback URL.
import type { Fetcher } from "./preview.ts";
import { assertPublicHttps } from "./urlguard.ts";

export async function notifyMerchant(callbackUrl: string, body: string, fetcher: Fetcher): Promise<void> {
  const target = assertPublicHttps(callbackUrl);
  target.searchParams.set("body", body);
  await fetcher(assertPublicHttps(target.toString()).toString());
}
