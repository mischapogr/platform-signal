# PLATFORM::SIGNAL architecture and AWS adoption presentation

[Open the HTML presentation](index.html). This is the maintained format: 41
offline slides in English for DevOps, SecOps and architects, with diagrams, graphs,
an interactive scenario calculator, speaker notes, contents, fullscreen and print.
Allow 40–45 minutes plus discussion, or select chapters from **Contents**.
Source/price snapshot: 7 July 2026. Arrow keys navigate; `N` toggles notes.

The deck covers target/current architecture, public mechanisms and private company
policy, a hypothetical AWS company, enterprise alternatives, onboarding/coverage,
restore and upgrade workflows, selected AWS resource inventories and message
volumes, infrastructure cost and post-stable-release maintenance effort.

| AWS accounts | Canonical GB/day | AWS baseline USD/month | Scheduled person-hours/month |
| ---: | ---: | ---: | ---: |
| 1 | 9.75 | $288 | 10–20 |
| 10 | 61.1 | $770 | 20–40 |
| 100 | 611 | $5,313 | 64–128 |
| 1,000 | 6,110 | $53,127 | 240–480 |

These are fictional selected estates and calculations, not supported capacity or
quotes. USD estimates use us-east-1 on-demand rates, 730 compute hours and 30
traffic days. AWS totals include modeled source-log delivery, exclude labor and
the business workload compute/database bill, and assume steady-state retention.
The one-account case cannot provide a separate security-account failure boundary.
The 1,000-account case is outside the current target envelope and is only a
ten-cell cost extrapolation, with no federation or availability promise.

The calculator changes traffic, retention, compression, loaded labor rate,
compute/disk allocation and inclusion of already-budgeted CloudWatch delivery.
It updates only the calculator; other slides show the frozen baseline. Traffic
changes do not qualify or automatically resize workers, control DB or labor.
**Reset baseline** restores comparisons. All calculations stay in the browser;
the deck needs no network access, external scripts or fonts.

Staffing bands assume the selected stable product/profile, automated operation
and qualified adapters. They include recurring platform maintenance and detection
policy tuning. Initial migration, new development, security investigations,
incident response, major migrations and staffed 24/7 coverage are additional.
Effort FTE uses 160 hours/month; assign primary/backup owners independently.

## Start the presentation

No checkout is needed. The deck is one self-contained HTML file with no network
dependencies.

| Situation | Command or link |
| --- | --- |
| Anywhere, any device | Open the published deck: `https://mischapogr.github.io/platform-signal/aws-adoption/`. It exists after the **Presentation** workflow has run on `main` and Pages is set to *GitHub Actions* (Settings → Pages). |
| One file, offline | `curl -fsSLo signal-deck.html https://raw.githubusercontent.com/mischapogr/platform-signal/main/docs/presentations/aws-adoption/index.html` then open it in a browser. Use `xdg-open`, `open` or `start`. |
| Only this folder from git | `git clone --depth 1 --filter=blob:none --sparse git@github.com:mischapogr/platform-signal.git && cd platform-signal && git sparse-checkout set docs/presentations docs/diagrams` |
| Full checkout | Open `docs/presentations/aws-adoption/index.html`. |

Press `F` or use **Fullscreen**. `#slide-12` in the URL opens a given slide; share it to point
colleagues at one slide. Click any diagram to enlarge it or to copy its Mermaid source or save SVG/PNG.
Source links in the deck are absolute GitHub URLs, so they work from a single file; they show the `main`
branch, which can be newer than the deck.

## Diagrams

Architecture and workflow diagrams are Mermaid files in [`docs/diagrams`](../../diagrams/README.md),
shared by the docs and the deck. That folder explains importing into Miro, FigJam, draw.io and Slack.
After editing a `.mmd` file run `docs/diagrams/render.sh`, then `build.py`.

## Neutrality and licensing

Product and company names are trademarks of their owners, used only to identify documented
products. No affiliation, endorsement, benchmark, quote or claim of superiority is made. Comparative
judgments are inferences from public pages and are labeled as such; verify against each vendor's
current terms. The deck uses no vendor logos, screenshots or copied marketing text. Pinned AWS rate
records are factual price points with their source URLs. Content is under the repository license.

## Editable source and evidence

- [Deck source](deck.json), [renderer](build.py) and
  [speaker notes](speaker-notes.md).
- [Detailed assumptions, formulas and exclusions](cost-assumptions.md),
  [model inputs](cost-model.json) and [shared calculation engine](cost-model.js).
- [Exact baseline results](estimate-baseline.json) and
  [CSV export](cost-estimates.csv).
- [Pinned public AWS rate records](pricing-snapshot.json), including source URL,
  publication date, SKU/rate code and source-file SHA256. Official service pricing
  links are also in the appendix. Comparative vendor judgments are inferences;
  no comparative benchmark, vendor quote or cost saving is claimed.

Regenerate HTML, notes and baseline exports using Python 3 and Node.js:

```bash
python3 docs/presentations/aws-adoption/build.py
```

Earlier PowerPoint and PDF exports are outside this maintained HTML-only
presentation and are not generated by this renderer. HTML can still be printed
using the supplied widescreen print CSS.

A single HTML copy works offline for presenting and calculating. Its evidence links
point at the repository on GitHub.

## Verification and handoff

After the 41-slide redesign, every slide was checked in Chromium at desktop size for content overflow and the diagram zoom dialog was opened. Mobile width, print layout and the PNG/SVG download buttons were not re-tested after the redesign. The actual
calculator controls were tested for source-charge exclusion, independent labor
rate changes, doubled traffic and reset. Accounting checks cover source/total
separation, DB instance counting, message arithmetic, S3 tier transitions and
retention independence. Final reports/screenshots are under
`target/presentation-aws-adoption/`.

Only presentation, diagram, `logical-architecture.md` and the Presentation workflow changed. No Rust/build input changed; no Cargo campaign
was needed. Existing concurrent work was preserved. No AWS resources were created or
presentation artifacts published.
No product phase or release qualification was advanced.

Single writer: Codex. Exact runtime model/effort and task-scoped usage/elapsed
telemetry were not separately captured; allowance/provider cost is unavailable.
Corrections addressed diagram label placement, calculator height and a browser
test's control-focus setup. No model/speed setting changed. Next presenter action:
replace assumed entity counts, source bytes, operator effort and routing with
actual company measurements before budget or production decisions.
