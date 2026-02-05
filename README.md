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
