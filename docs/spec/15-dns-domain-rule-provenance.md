# 15 — DNS Domain Rule Provenance (Dataset: 6 classes)

## Scope

The Flow dataset label mapping contains six classes: `other-web`, `facebook`, `chatgpt`, `tiktok`, `youtube`, and `spotify`. The supplied dataset snapshot reports 25,263 Flow windows. The DNS rule file covers only service-specific domains for the five named applications.

`other-web` is deliberately **not** configured as a DNS catch-all. DNS rules are positive evidence only. An unmatched domain remains DNS-unresolved and may proceed to SNI, then Burst ML. This prevents every unrelated or newly encountered domain from being prematurely labeled `other-web`.

## Included domain families

| Application ID | Domain suffixes configured |
|---|---|
| `chatgpt` | `chatgpt.com`, `chat.openai.com` |
| `facebook` | `facebook.com`, `facebook.net`, `fbcdn.net`, `fbsbx.com`, `fb.com`, `fb.me` |
| `tiktok` | `tiktok.com`, `tiktokapis.com`, `tiktokcdn.com`, `tiktokcdn-eu.com`, `tiktokcdn-us.com`, `tiktokv.com`, `tiktokv.eu`, `tiktokv.us`, `tiktokw.eu`, `tiktokw.us`, `ttwstatic.com` |
| `youtube` | `youtube.com`, `youtu.be`, `googlevideo.com`, `ytimg.com`, `youtube-nocookie.com`, `youtubei.googleapis.com`, `youtube.googleapis.com`, `yt3.ggpht.com` |
| `spotify` | `spotify.com`, `spoti.fi`, `scdn.co`, `pscdn.co`, `spotifycdn.com`, `spotifycdn.net` |

All configured entries use label-aware `suffix` matching. For example, `api.chatgpt.com` matches `chatgpt.com`, while `notchatgpt.com` does not.

## Deliberate exclusions

- No IP address rules. Shared IP/CDN addresses are not application identity.
- No generic provider roots such as `google.com`, `googleapis.com`, `gstatic.com`, `cloudflare.com`, `amazonaws.com`, or `akamaized.net`.
- No broad `openai.com` suffix: it can include OpenAI services other than the ChatGPT user-facing application. Add narrower observed ChatGPT hostnames only after validating them against labeled captures.
- No generic ByteDance infrastructure roots such as `byteoversea.com` or `ibytedtos.com`, because they may be shared by multiple ByteDance products.
- No Instagram, Messenger, WhatsApp, or Threads domains under the `facebook` label. The dataset class is specifically `facebook`, not all Meta products.
- No `other-web` catch-all rule.

## Provenance references

The initial seed list was cross-checked against:

- OpenAI Help Center, “Network recommendations for ChatGPT errors on web and apps”: https://help.openai.com/en/articles/9247338-network-recommendations-for-chatgpt-errors-on-web-and-apps
- Google Workspace Help, “Control YouTube content available to users”: https://knowledge.workspace.google.com/admin/youtube/control-youtube-content-available-to-users
- Cisco Community, YouTube domain bypass list (`youtube.com`, `googlevideo.com`, `youtu.be`, `ytimg.com`, YouTube API hostnames): https://community.cisco.com/t5/secure-access-announcements/youtube-com-bot-warning-message-for-secure-access-swg/tac-p/5567910
- Netify Facebook application domain overview: https://www.netify.ai/resources/applications/facebook
- WhoGetsMyData Meta domain observations (used only to cross-check Facebook-owned domain families, not to include Instagram/WhatsApp/Threads): https://whogetsmydata.com/company/meta
- TikTok observed domain families: https://whogetsmydata.com/company/tiktok and https://github.com/nextdns/services/blob/main/services/tiktok
- Spotify domain list: https://github.com/v2fly/domain-list-community/blob/master/data/spotify

These are seed rules, not a guarantee that every client version, region, or app feature uses only these domains. The authoritative refinement loop is to collect DNS/PCAP evidence during isolated, labeled app sessions and review each newly observed hostname before adding it.

## Operational caveat

DNS identification requires a correlated successful DNS response, client-scoped cache evidence, valid TTL, and an unambiguous application mapping. If a shared IP has live candidate domains from multiple application IDs, the DNS identifier must return unresolved; it must not pick one app by recency, TTL, or frequency.
