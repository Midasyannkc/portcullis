import test from "node:test";
import assert from "node:assert/strict";
import { linkPreview } from "../src/preview.ts";
import { notifyMerchant } from "../src/webhook.ts";
import { renderNote } from "../src/render.ts";
import { newSessionToken, transferHandler } from "../src/session.ts";

test("preview fetches https urls", async () => {
  assert.equal(await linkPreview("https://example.com/a", async (u) => "ok:" + u), "ok:https://example.com/a");
});
test("webhook posts to merchant", async () => {
  const seen: string[] = [];
  await notifyMerchant("https://merchant.example/hook", "paid", async (u) => { seen.push(u); return ""; });
  assert.equal(seen.length, 1);
});
test("plain notes render", () => { assert.equal(renderNote("hello"), '<p class="note">hello</p>'); });
test("tokens are 32 hex chars", () => { assert.match(newSessionToken(), /^[0-9a-f]{32}$/); });
test("logged in POST transfers", () => {
  const l = { transfers: [] as { to: string; amount: number }[] };
  assert.equal(transferHandler({ method: "POST", cookies: { session: "s" }, headers: {}, body: { to: "a", amount: 1 } }, new Set(["s"]), l), 200);
  assert.equal(l.transfers.length, 1);
});
