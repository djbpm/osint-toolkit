# osint-toolkit

An intelligence-focused index of **OSINT**, **Cyber Threat Intelligence (CTI)**, and **public data investigation** tools.

This repository is designed for:
- OSINT practitioners
- Threat intelligence analysts
- Security researchers
- Investigators & journalists

The focus is **methodology-first**, not tool spam.

---

## Scope & Philosophy

- Open-source and publicly accessible resources only
- No leaked databases or illegal content
- Tools are categorized by **investigation objective**, not popularity
- Emphasis on **signal over noise**

---

## Table of Contents

- General Search & Discovery  
- Google Dorks & Advanced Search  
- Threat Intelligence & CTI  
- Domains, IPs & Infrastructure  
- Data Breaches & Credential Exposure  
- Social Media Intelligence (SOCMINT)  
- Image & Video Intelligence (IMINT / VIDINT)  
- Geospatial Intelligence (GEOINT)  
- Dark Web & Underground Sources  
- Automation & Frameworks  
- Research, Academia & Reports  

 ## General Search & Discovery
Core search engines and discovery platforms used during OSINT and CTI investigations.
- **[Google Search](https://www.google.com)** — Advanced operators and indexing for open-source research.
- **[Bing](https://www.bing.com)** — Alternative indexing that often surfaces assets missed by Google.
- **[DuckDuckGo](https://duckduckgo.com)** — Privacy-focused search engine useful for neutral and de-biased queries.
- **[Yandex](https://yandex.com)** — Strong coverage for Eastern European and Russian-language content.
- **[Perplexity](https://www.perplexity.ai)** — AI-assisted search with cited sources and traceable references.
- **[Mojeek](https://www.mojeek.com)** — Independent crawler-based search engine with minimal tracking.
- **[Swisscows](https://swisscows.com)** — Privacy-first search engine hosted in Switzerland.
- **[Gigablast](https://www.gigablast.com)** — Open-source inspired search engine with its own index.
- **[Marginalia Search](https://search.marginalia.nu)** — Focuses on non-commercial, independent web content.
- **[Internet Archive Search](https://archive.org)** — Search across archived web pages, documents, and media.
- **[Wolfram Alpha](https://www.wolframalpha.com)** — Structured, computational intelligence for factual queries.

- ## Google Dorks & Advanced Search

Advanced search operators and query techniques used to discover publicly exposed information indexed by search engines.

These methods are widely used in OSINT, threat intelligence, and security research to identify misconfigurations, exposed assets, and sensitive data leaks.

---

### Official Documentation & References

- **Google Advanced Search Operators**  
  https://support.google.com/websearch/answer/2466433

- **Google Search Help Center**  
  https://www.google.com/advanced_search

- **OWASP Google Dorking Guide**  
  https://owasp.org/www-community/attacks/Google_Hacking

- **Exploit Database – Google Hacking Database (GHDB)**  
  https://www.exploit-db.com/google-hacking-database

---

### Common Google Dork Operators
- **site:** Limit results to a specific domain  
  - Example: `site:example.com`

- **filetype:** Search for specific file formats  
  - Example: `filetype:pdf`, `filetype:xlsx`, `filetype:sql`

- **intitle:** Search for keywords in page titles  
  - Example: `intitle:"index of"`

- **inurl:** Search for keywords within URLs  
  - Example: `inurl:admin`

- **cache:** View cached versions of pages  
  - Example: `cache:example.com`

- **related:** Find websites related to a domain  
  - Example: `related:example.com`

---

### Sensitive Information Discovery

Used to identify unintentionally exposed files and documents.

- Configuration files  
  - `filetype:env`
  - `filetype:yaml`
  - `filetype:ini`

- Backup and archive files  
  - `filetype:zip`
  - `filetype:tar`
  - `filetype:bak`

- Credential-related documents  
  - `filetype:txt password`
  - `filetype:xlsx credentials`

---

### Directory Listing & Open Indexes

Identify misconfigured web servers exposing directory contents.

- `intitle:"index of"`
- `intitle:"index of" backup`
- `intitle:"index of" confidential`

Reference:
- https://www.exploit-db.com/google-hacking-database?category=Files

---

### Cloud & DevOps Exposure

Discover publicly indexed cloud resources and development artifacts.

- Cloud storage references  
  - `site:s3.amazonaws.com`
  - `site:blob.core.windows.net`
  - `site:storage.googleapis.com`

- CI/CD and development files  
  - `filetype:yml github`
  - `filetype:json api_key`
  - `filetype:log password`

References:
- https://cloud.google.com/security
- https://owasp.org/www-project-top-ten/

---

### Ethical Use Notice

Google dorking should only be performed for **educational, defensive, and lawful research purposes**.

Researchers should avoid interacting with exposed systems or downloading sensitive data.

## Threat Intelligence & CTI

Tools, platforms, and data sources used to identify, track, and analyze cyber threats, threat actors, infrastructure, and campaigns.

### Threat Intelligence Platforms
- **AlienVault OTX** — Community-driven threat intelligence and IOC sharing.  
  https://otx.alienvault.com/
- **VirusTotal** — Malware scanning and indicator enrichment using multiple engines.  
  https://www.virustotal.com/
- **Hybrid Analysis** — Automated malware behavior analysis sandbox.  
  https://www.hybrid-analysis.com/
- **MalwareBazaar** — Malware sample repository with hashes and metadata.  
  https://bazaar.abuse.ch/
- **ANY.RUN** — Interactive online malware sandbox environment.  
  https://any.run/
  ### Threat Feeds & IOC Sources
- **AbuseIPDB** — Reputation database of malicious IP addresses.  
  https://www.abuseipdb.com/
- **Spamhaus** — Intelligence on spam, botnets, and malicious infrastructure.  
  https://www.spamhaus.org/
- **Feodo Tracker** — Tracking command-and-control servers for botnets.  
  https://feodotracker.abuse.ch/
- **URLhaus** — Collection of malicious URLs used for malware distribution.  
  https://urlhaus.abuse.ch/
- **PhishTank** — Verified phishing URLs and phishing intelligence.  
  https://phishtank.org/
  ### Threat Actor & Campaign Research
- **MITRE ATT&CK** — Knowledge base of adversary tactics, techniques, and procedures (TTPs).  
  https://attack.mitre.org/
- **MISP** — Open-source platform for sharing threat intelligence and indicators.  
  https://www.misp-project.org/
- **OpenSanctions** — Sanctions lists, PEPs, and high-risk entities database.  
  https://www.opensanctions.org/
- **IntelX** — Search engine for leaked data, dark web content, and technical artifacts.  
  https://intelx.io/
### Infrastructure & Exposure Analysis
- **Shodan** — Search engine for internet-exposed devices and services.  
  https://www.shodan.io/
- **Censys** — Internet-wide asset discovery and infrastructure intelligence.  
  https://search.censys.io/
- **GreyNoise** — Differentiates background internet noise from real threats.  
  https://www.greynoise.io/
- **Pulsedive** — Threat intelligence enrichment and risk analysis platform.  
  https://pulsedive.com/

  ## Domains, IPs & Infrastructure

Tools and services used to analyze domains, IP addresses, hosting infrastructure, certificates, DNS records, and exposed services.

### Domain & DNS Intelligence
- **WHOIS** — Domain registration records and ownership metadata.  
  https://who.is/
- **ViewDNS** — DNS records, reverse IP lookup, and historical DNS data.  
  https://viewdns.info/
- **SecurityTrails** — Domain, DNS, and infrastructure history tracking.  
  https://securitytrails.com/
- **DomainTools** — Domain ownership, pivoting, and risk profiling.  
  https://www.domaintools.com/
- **DNSDumpster** — DNS recon and subdomain discovery tool.  
  https://dnsdumpster.com/
### IP & Network Intelligence
- **IPinfo** — IP geolocation, ASN, and network ownership data.  
  https://ipinfo.io/
- **ARIN / RIPE / APNIC** — Regional internet registry lookups.  
  https://www.arin.net/  
  https://www.ripe.net/  
  https://www.apnic.net/
- **BGPView** — ASN, prefix, and BGP routing information.  
  https://bgpview.io/
- **IPVoid** — IP reputation and blacklist checking.  
  https://www.ipvoid.com/

### Internet-Wide Scanning & Exposure
- **Shodan** — Discover exposed services, devices, and banners.  
  https://www.shodan.io/
- **Censys** — Internet asset discovery using certificates and scans.  
  https://search.censys.io/
- **ZoomEye** — Cyberspace search engine for exposed assets.  
  https://www.zoomeye.org/
- **FOFA** — Search engine for internet-connected devices and services.  
  https://fofa.info/
  ### Certificates & Web Infrastructure
- **crt.sh** — Certificate Transparency logs for subdomain discovery.  
  https://crt.sh/
- **CertSpotter** — SSL certificate monitoring and alerts.  
  https://certspotter.com/
- **BuiltWith** — Website technology stack profiling.  
  https://builtwith.com/
- **Wappalyzer** — Identify technologies used on websites.  
  https://www.wappalyzer.com/
  ### Cloud & Hosting Attribution
- **GrayHat Warfare** — Public cloud storage exposure search.  
  https://grayhatwarfare.com/
- **PublicWWW** — Source code and technology fingerprint search.  
  https://publicwww.com/
- **Hunter.io** — Domain-based email infrastructure discovery.  
  https://hunter.io/

  ## Data Breaches & Credential Exposure

Resources used to identify leaked credentials, breached accounts, exposed databases, and compromised personal or corporate data.

### Breach & Credential Lookup
- **Have I Been Pwned** — Check emails and usernames against known data breaches.  
  https://haveibeenpwned.com/
- **DeHashed** — Search leaked credentials, emails, usernames, IPs, and domains.  
  https://www.dehashed.com/
- **BreachDirectory** — Aggregated breach data search for emails and usernames.  
  https://breachdirectory.org/
- **LeakCheck** — Credential leak detection for emails, usernames, and domains.  
  https://leakcheck.io/
- **IntelX (Intelligence X)** — Search leaked datasets, documents, and credentials.  
  https://intelx.io/
  ### Password & Combo List Intelligence
- **Scylla.sh** — Search engine for leaked passwords and credential dumps.  
  https://scylla.sh/
- **Snusbase** — Breach database search for usernames, emails, and passwords.  
  https://snusbase.com/
- **WeLeakInfo (Archived)** — Historical breach intelligence reference.  
  https://weleakinfo.to/

### Paste & Leak Monitoring
- **Pastebin** — Public paste monitoring for leaked credentials and data.  
  https://pastebin.com/
- **Pastebin Archive** — Historical paste indexing and analysis.  
  https://psbdmp.cc/
- **Ghostbin** — Anonymous text sharing often used for leaks.  
  https://ghostbin.com/
  ### Dark Web & Marketplace Monitoring
- **DarkSearch** — Search engine for Tor (.onion) content.  
  https://darksearch.io/
- **Ahmia** — Tor search engine with indexed onion services.  
  https://ahmia.fi/
- **OnionSearch** — Command-line tool for searching Tor networks.  
  GitHub - megadose/OnionSearch: OnionSearch is a script that scrapes urls on different .onion search
  #### Enterprise & Defensive Monitoring
- **SpyCloud** — Enterprise breach monitoring & ATO prevention.  
  https://spycloud.com/
- **Constella Intelligence** — Digital identity risk & breach intelligence.  
  https://constella.ai/
- **RiskIQ (PassiveTotal)** — Infrastructure & breach correlation.  
  https://community.riskiq.com/

#### Ethical & Legal Use
All tools listed are intended for **defensive security, threat intelligence, fraud prevention, and OSINT research**.  
Misuse of leaked data or unauthorized access is illegal and unethical.

## Social Media Intelligence (SOCMINT)
FACEBOOK

🟢 Facebook Friend List Scraper
https://github.com/
Purpose: Scrape large Facebook friend lists without aggressive rate limiting.

🟢 Facebook Search
https://www.facebook.com/search/
Purpose: Native Facebook graph search for people, posts, pages, and groups.

🟢 Fanpage Karma
https://www.fanpagekarma.com/
Purpose: Analyze Facebook page engagement, growth, and performance.

🟢 FB Sleep Stats
https://github.com/
Purpose: Behavioral analysis using Facebook activity timestamps.

🟢 Find My Facebook ID
https://findmyfbid.com/
Purpose: Resolve numeric Facebook IDs for profiles, pages, and groups.

🟢 Have I Been Zuckered
https://haveibeenzuckered.com/
Purpose: Check if phone numbers appeared in historic Facebook breaches.
  
🟢 Lookup-ID
https://lookup-id.com/
Purpose: Extract Facebook profile, group, and page IDs.

🟢 Search Is Back
https://searchisback.com/
Purpose: Advanced keyword and people search on Facebook.

🆕 IntelX Facebook Datasets
https://intelx.io/
Purpose: Search leaked Facebook-related datasets and identifiers.

🆕 CrowdTangle (Meta)
https://www.crowdtangle.com/
Purpose: Track public Facebook content spread and engagement (journalism/research).

INSTAGRAM

  🟢 Dolphin Radar
https://dolphinradar.com/
Purpose: View public Instagram posts, stories, and profiles anonymously.

🟢 Iconosquare
https://www.iconosquare.com/
Purpose: Instagram analytics and engagement intelligence.

🟢 Instagram Monitor
GitHub · Change is constant. GitHub keeps you ahead.
Purpose: Track Instagram profile changes and activity in real time.

🟢 InstagramPrivSniffer
GitHub · Change is constant. GitHub keeps you ahead.
Purpose: Research access to private Instagram media (OSINT use).

🟢 Osintgram
GitHub - Datalux/Osintgram: Osintgram is a OSINT tool on Instagram. It offers an interactive shell t
Purpose: CLI OSINT tool for Instagram usernames, emails, and metadata.

🟢 Osintgraph
GitHub · Change is constant. GitHub keeps you ahead.
Purpose: Visualize Instagram relationships using Neo4j.

🟢 Toutatis
GitHub · Change is constant. GitHub keeps you ahead.
Purpose: Extract emails, phone numbers, and metadata from Instagram accounts.

🆕 Inflact Tools
https://inflact.com/
Purpose: Username, hashtag, and profile intelligence for Instagram.

🆕 Picuki
https://www.picuki.com/
Purpose: Anonymous Instagram browsing and content inspection.

TWITTER/X

🟢 Twitter Advanced Search
https://twitter.com/search-advanced
Purpose: Filter tweets by keywords, users, dates, and engagement.

🟢 Twint
GitHub - twintproject/twint: An advanced Twitter scraping & OSINT tool written in Python that doesn'
Purpose: Scrape tweets without API access.

🟢 TweetMap
https://www.omnisci.com/demos/tweetmap
Purpose: Visualize tweets by geolocation.

🟢 Trends24
https://trends24.in/
Purpose: Monitor trending topics by country and city.

🆕 Twemex
https://twemex.app/
Purpose: Search Twitter bios, followers, and conversations.

🆕 Followerwonk
https://followerwonk.com/
Purpose: Analyze Twitter/X followers and bios.

REDDIT

🟢 Arctic Shift
https://arctic-shift.photon-reddit.com/
Purpose: Access historical Reddit data via API and web UI.

🟢 Pushshift API
https://pushshift.io/
Purpose: Search deleted and archived Reddit posts/comments.

🟢 PullPush
https://pullpush.io/
Purpose: Investigate removed Reddit submissions and comments.

🟢 Reddit Comment Search
https://redditcommentsearch.com/
Purpose: Search comments by username.

🟢 Reddit Universal scammers list
https://www.universalscammerlist.com/
Purpose:This acts as the website-portion for the subreddit /r/universalscammerlist.

🆕 Reveddit
https://www.reveddit.com/
Purpose: Detect removed or censored Reddit content.

🆕 Unddit
https://unddit.com/
Purpose: View deleted Reddit comments in near real time.

PINTEREST

🟢 Pingroupie
https://pingroupie.com/
Purpose: Discover Pinterest group boards and contributors.

🟢 Pinterest Pin Stats
https://www.pinterest.com/
Purpose: Analyze hidden engagement metrics for Pinterest pins.

WHATSAPP

🟢 WhatsApp Click-to-Chat
https://wa.me/
Purpose: Verify if a phone number is registered on WhatsApp.

🟢 WhatsApp Group Links Search
https://www.whatsapgrouplinks.org/
Purpose: Discover public WhatsApp groups via indexed invite links.

🟢 WhatsApp Monitor (Metadata)
GitHub · Change is constant. GitHub keeps you ahead.
Purpose: Analyze profile photo changes, status timing, and online indicators.

🆕 CallMeBot WhatsApp
https://www.callmebot.com/
Purpose: Trigger WhatsApp interactions for number verification workflows.

VKontakte

🟢 VK People Search
https://vk.com/search
Purpose: Search VK users by name, city, education, and employer.

🟢 VK Watch
GitHub · Change is constant. GitHub keeps you ahead.
Purpose: Monitor VK profiles for changes in posts, photos, and friends.

🟢 VK Profile Analyzer
https://vk.com/app
Purpose: Extract public VK metadata including groups and interests.

🆕 SocialGrep VK
https://socialgrep.com/
Purpose: Keyword search across VK posts and comments.

DISCORD

🟢 Discord Server Discovery
https://disboard.org/
Purpose: Discover public Discord servers by topic, language, and keywords.

🟢 Discord.me
https://discord.me/
Purpose: Index of public Discord servers and communities.

🟢 DiscordServers
https://discordservers.com/
Purpose: Search and analyze public Discord communities.

🟢 Discord ID Lookup
https://discord.id/
Purpose: Resolve user, server, and channel IDs from Discord profiles.

🟢 Discord Lookup
https://discordlookup.com/
Purpose: Fetch public Discord user metadata and avatar history.

🟢 Discord History Tracker
https://github.com/
Purpose: Track message edits, deletions, and activity patterns (where permitted).

🟢 Discord Chat Exporter
GitHub - Tyrrrz/DiscordChatExporter: Saves Discord chat logs to a file
Purpose: Export Discord messages for offline analysis and evidence preservation.

🟢 Discord OSINT Toolkit
GitHub · Change is constant. GitHub keeps you ahead.
Purpose: Collection of scripts for Discord reconnaissance and metadata analysis.

🆕 SocialGrep (Discord)
https://socialgrep.com/
Purpose: Keyword search across public Discord message datasets.

🆕 IntelligenceX (Discord)
https://intelx.io/
Purpose: Search indexed Discord leaks, chats, and shared artifacts.

TELEGRAM

🟢 TgramSearch
https://tgramsearch.com/
Purpose: Search Telegram channels and groups by keyword.

🟢 Telegram Finder
GitHub · Change is constant. GitHub keeps you ahead.
Purpose: Identify Telegram users via phone, email, or LinkedIn.

🟢 Telemetr
https://telemetr.io/
Purpose: Telegram channel analytics and discovery.

🟢 Telegago
https://telegago.com/
Purpose: Google-style dorking for Telegram channels.

🟢 Telepathy
GitHub · Change is constant. GitHub keeps you ahead.
Purpose: Archive and analyze Telegram conversations.

🟢 Tosint
GitHub · Change is constant. GitHub keeps you ahead.
Purpose: OSINT extraction from Telegram bots and channels.

🆕 TGStat
https://tgstat.com/
Purpose: Telegram channel statistics and influence tracking.

🆕 Lyzem
https://lyzem.com/
Purpose: Monitor Telegram narratives and disinformation.

TELEGRAM BOTS

Identity, Username & Account Analysis
- **@MaigretOSINTBot**  
  Username search across 1,000+ websites directly from Telegram.  
  Purpose: Identity correlation & footprint mapping.

- **@SangMataInfo_bot**  
  Shows historical Telegram username changes.  
  Purpose: Alias tracking & evasion detection.

- **@creationdatebot**  
  Estimates Telegram account creation date.  
  Purpose: Sockpuppet & burner account analysis.

- **@username_to_id_bot**  
  Converts usernames to Telegram user/channel IDs.  
  Purpose: Metadata resolution & automation workflows.

  Phone Number & Email Intelligence
- **@DetectivaBot**  
  Phone & email OSINT search across multiple datasets.  
  Purpose: Identity enrichment & cross-platform correlation.

- **@LeakOSINTBot**  
  Checks phone numbers and emails against leaked datasets.  
  Purpose: Breach exposure verification.

- **@PasswordSearchBot**  
  Searches leaked credentials linked to emails.  
  Purpose: Account takeover & credential reuse analysis.

- **@Sherlock_OSINT_Bot**  
  Username, phone, and email lookup.  
  Purpose: Rapid reconnaissance.

  Vehicle, Property & Regional Intelligence

  - **@AVinfoBot**  
  Vehicle history via plate, VIN, or phone number.  
  Purpose: Asset & fraud investigations.

- **@AutoNomerBot**  
  Finds vehicle images by license plate.  
  Purpose: Visual verification & geolocation hints.
  
  Geolocation & Network Metadata

  - **@GeoMacFinderBot**  
  Wi-Fi access point location via BSSID/MAC address.  
  Purpose: Geolocation pivoting.

- **@WhoisDomBot**  
  Domain & IP WHOIS lookups inside Telegram.  
  Purpose: Infrastructure reconnaissance.

- **@IPScoreBot**  
  IP reputation & risk scoring.  
  Purpose: Fraud & abuse analysis

  Dark Web & Threat Intelligence

  - **@IntelXBot**  
  Interface to Intelligence X datasets (leaks, dark web, documents).  
  Purpose: Threat intel & breach investigations.

- **@DarkWebInformerBot**  
  Tracks threat actors, leaks, and underground activity.  
  Purpose: Early-warning intelligence.

- **@OnionScanBot**  
  Onion service metadata lookup.  
  Purpose: Dark web infrastructure awareness.

  Channel, Group & Message Discovery

- **@TGStatBot**  
  Telegram channel analytics and discovery.  
  Purpose: Influence & reach analysis.

- **@TelemetrBot**  
  Channel statistics, trends, and growth metrics.  
  Purpose: Propaganda & campaign monitoring.

- **@SearchForChatsBot**  
  Search Telegram chats by keywords.  
  Purpose: Topic-based reconnaissance.

- **@SurftgBot**  
  Message-level search across Telegram.  
  Purpose: Content & narrative tracking.

 Advanced OSINT & Automation

- **@HimeraSearchBot**  
  Aggregated OSINT search (people, phones, vehicles, courts).  
  Purpose: Multi-source intelligence pivoting.

- **@OsintKitBot**  
  Ukrainian-focused OSINT (phones, emails, IDs, vehicles).  
  Purpose: Regional intelligence research.

- **@OpenSourceIntelBot**  
  General OSINT utilities and quick lookups.  
  Purpose: Rapid analyst workflows.
  

TUMBLR

🟢 Tumblr Search
https://www.tumblr.com/search
Purpose: Native Tumblr keyword and tag search.

🟢 Tumblr Tool
GitHub · Change is constant. GitHub keeps you ahead.
Purpose: Extract posts, likes, followers, and reblogs from Tumblr blogs.

🟢 TumblThree
GitHub - johanneszab/TumblThree: A Tumblr Blog Backup Application
Purpose: Archive Tumblr blogs locally for analysis.

🆕 Tumblr Tag Viewer
https://tumblr.com/tagged/
Purpose: Track communities and trends via Tumblr tags.

LINKEDLN

🟢 LinkedIn Search
https://www.linkedin.com/search/
Purpose: Search people, companies, jobs, and posts.

🟢 LinkedIn X-Ray (Google Dork)
site:linkedin.com/in
Purpose: Discover profiles bypassing LinkedIn search limits.

🟢 LinkedInt
GitHub - vysecurity/LinkedInt: LinkedIn Recon Tool
Purpose: OSINT tool to gather LinkedIn employee data.

🟢 Hunter LinkedIn Extension
https://hunter.io/
Purpose: Discover corporate email formats from LinkedIn profiles.

🆕 PhantomBuster
https://phantombuster.com/
Purpose: Automate LinkedIn data collection and enrichment.

STEAM

🟢 OSINT-Steam
GitHub · Change is constant. GitHub keeps you ahead.
Purpose: Extract public Steam profile data and friends lists.

🟢 SteamID Finder
https://steamid.io/
Purpose: Resolve SteamID, vanity URLs, and linked accounts.

🟢 SteamRep
https://steamrep.com/
Purpose: Reputation and abuse intelligence for Steam accounts.

🆕 SteamDB
https://steamdb.info/
Purpose: Analyze Steam account activity, ownership, and metadata

GITHUB

🟢 GitHub Search
Build software better, together
Purpose: Search users, repositories, commits, and code.

🟢 GitHub Monitor
GitHub · Change is constant. GitHub keeps you ahead.
Purpose: Track GitHub user activity and repository changes.

🟢 GitHubRecon
GitHub · Change is constant. GitHub keeps you ahead.
Purpose: Username and email reconnaissance on GitHub.

🟢 Shhgit
https://github.com/eth0izzle/shhgit
Purpose: Detect leaked secrets in GitHub repositories.

🆕 TruffleHog
GitHub - trufflesecurity/trufflehog: Find, verify, and analyze leaked credentials
Purpose: Scan GitHub for exposed credentials and secrets.

TikTok

- TikTok Timestamp — https://tiktoktimestamp.com
  Determine the exact publication time of a TikTok video.

- TikStats — https://tikstats.org
  Detailed growth statistics for TikTok accounts.

- TikTok Scraper — https://github.com/drawrowfly/tiktok-scraper
  Scrape videos, users, hashtags, and metadata.

- TikTok Downloader — https://ssstik.io
  Download TikTok videos.

- TikTokD — https://tiktokd.com
  TikTok video downloader.

- Snaptik — https://snaptik.app
  TikTok video downloader.

- TikTake — https://tiktake.net
  TikTok video downloader.

- Exolyt — https://exolyt.com
  TikTok profile analytics.

- TikBuddy — https://tikbuddy.com
  TikTok profile analytics.

- MaveKite — https://mavekite.com
  Engagement analytics for last 40 videos.

- TikRank — https://tikrank.com
  Country-based TikTok ranking and comparison.

- TikTok Creative Center — https://ads.tiktok.com/business/creativecenter
  Trending hashtags, songs, creators, and videos.

OnlyFans

- FansMetrics — https://fansmetrics.com
  Search across millions of OnlyFans accounts.

- OnlySearch — https://onlysearch.co
  OnlyFans user search engine.

- OnlyFinder — https://onlyfinder.com
  Search profiles by people, images, and deals.

- Hubite OnlyFans Search — https://hubite.com/onlyfans-search
  OnlyFans profiles search with price filters.

- SimilarFans — https://similarfans.com
  Find OnlyFans profiles using advanced filters.

- FanSearch — https://fansearch.com
  Search OnlyFans profiles by country, price, or category.

Twitch

- Twitch Tools — https://twitch-tools.rootonline.de
  Export full follower lists and channel data.

- Twitch Tracker — https://twitchtracker.com
  Detailed Twitch streamer analytics.

- SullyGnome — https://sullygnome.com
  Advanced Twitch statistics and trends.

- Twitch Stream Filter — https://www.twitch.tv/directory
  Filter streams by game, title, language, viewers.

- Untwitch — https://untwitch.com
  Twitch video downloader.

- Twitch Overlap — https://twitchoverlap.com
  Audience overlap between Twitch channels.

- Justlog — https://justlog.tv
  Export Twitch chat messages.

- Pogu Live — https://pogu.live
  Watch deleted or sub-only VODs.

- Twitch Recover — https://github.com/TwitchRecover/TwitchRecover
  Recover deleted Twitch VODs.

- Twitch Database — https://twitchdatabase.com
  Followers, channel metadata, and role lookup.

- Twitch Insights — https://twitchinsights.net
  Account stats, bots, extensions, teams.

- Twitch Followage Tool — https://twitch.followage.io
  View follow history with dates.

Spotify

- ZSpotify — https://github.com/Footsiefat/zspotify
  Spotify track downloader.

- Chosic — https://www.chosic.com
  Analyze playlists, moods, genres, decades.

- Spotify Downloader — https://spotifydown.com
  Download Spotify playlists via YouTube.

- ChartMasters Spotify Tool — https://chartmasters.org/spotify-streaming-numbers-tool/
  Spotify streaming statistics.

Roblox

- Rolimon’s — https://www.rolimons.com
  Roblox user stats, limited items, trade history, value tracking.

- RBLX.trade — https://rblx.trade
  Roblox limited item values and trading analysis.

- Bloxlink — https://blox.link
  Link Roblox accounts with Discord; useful for cross-platform pivoting.

- Roblox Username History — https://www.roblox.com/users/profile?username=
  Check past usernames by pivoting from profile data.

- Roblox API Explorer — https://create.roblox.com/docs/reference/engine
  Query user, game, asset, and group metadata via official APIs.

- Roblox Group Finder — https://www.roblox.com/groups
  Identify groups a user owns or participates in.

- RoSearcher — https://github.com/sixsixfive/RoSearcher
  Roblox username enumeration and profile lookup.

- Roblox Badge Finder — https://www.roblox.com/develop
  Analyze badges earned across games to infer behavior patterns.

- Roblox Game History — https://www.roblox.com/users/profile
  View public play history and created games.

- Roblox Catalog — https://www.roblox.com/catalog
  Pivot on avatar items, accessories, and ownership links.

Minecraft

- MineSight — https://minesight.gg
  OSINT by Minecraft nickname: servers, history, linked socials.

Xbox

- XboxGamertag — https://xboxgamertag.com
  Search Xbox Live users and gaming history.

Office365

- Oh365UserFinder — https://github.com/dievus/Oh365UserFinder
  Check if an email is tied to Office365.

- o365chk — https://github.com/0xZDH/o365chk
  Enumerate Office365 domains and instances.

OneDrive

- OneDrive Enumeration Tool — https://github.com/nyxgeek/onedrive_user_enum
  Enumerate OneDrive users within a company domain.

Udemy

- Udemy Video Playback Speed — https://chrome.google.com/webstore/detail/udemy-video-playback-speed
  Control video playback speed on Udemy.


BLOGSEARCH

🟢 BlogSearchEngine
https://www.blogsearchengine.org/
Purpose: Search blog posts by keyword and topic.

🟢 Notey
https://notey.com/
Purpose: Discover niche blogs and authors.

🟢 Twingly
https://www.twingly.com/
Purpose: Track blog mentions and influence.

🆕 Substack Search
https://substack.com/search
Purpose: Identify writers, newsletters, and narratives.

FORUMS

🟢 4chan Search
https://4chansearch.com/
Purpose: Search threads and archives across 4chan boards.

🟢 BoardReader
https://boardreader.com/
Purpose: Meta-search engine for forums and message boards.

🟢 BuiltWith Forum Lookup
https://builtwith.com/
Purpose: Identify forum platforms used by websites.

🟢 Facebook Groups
https://www.facebook.com/groups/
Purpose: Investigate public group discussions and members.

🟢 Google Groups
https://groups.google.com/
Purpose: Search historical mailing lists and discussions.

🟢 LinkedIn Groups
https://www.linkedin.com/groups/
Purpose: Professional discussion and network intelligence.

🟢 Yahoo Groups Archive
https://archive.org/
Purpose: Access archived Yahoo Groups discussions.

🆕 Discourse Search
https://www.discourse.org/
Purpose: Investigate modern forums running on Discourse.







​​​


## Contribution Guidelines
Communicate responsibly. Ensure message is publicly acceptable.​​​









This project welcomes **high-signal contributions**.

When adding a tool:
- Provide a **short, factual description**
- Avoid marketing language
- Prefer official links or documentation
- One tool per bullet

See `CONTRIBUTING.md` for details.

---

## Disclaimer

This repository is for **educational and defensive research purposes only**.  
The maintainer does not endorse misuse or illegal activity.
