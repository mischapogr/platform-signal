# Architecture diagrams

Diagrams are [Mermaid](https://mermaid.js.org) text files, so they review in pull requests,
render natively on GitHub and import into whiteboard and chat tools. The
[presentation](../presentations/aws-adoption/README.md) embeds the rendered SVGs.

| File | Shows | Status of what it draws |
| --- | --- | --- |
| [01-system-context](01-system-context.mmd) | People, sources, storage, private overlay | Target; today one local-filesystem server |
| [02-logical-architecture](02-logical-architecture.mmd) | Responsibilities with failure domains F1–F7 | Target; same diagram as [logical-architecture.md](../logical-architecture.md) |
| [03-aws-account-topology](03-aws-account-topology.mmd) | Workload, observability and security accounts | Target Standard profile |
| [04-acknowledgement-milestones](04-acknowledgement-milestones.mmd) | M0–M7 custody milestones | M2 and M4 current, others proposed |
| [08-logical-overview](08-logical-overview.mmd), [09-custody-ladder](09-custody-ladder.mmd) | Slide-sized overviews of 02 and 04; the deck shows these and opens the full diagram when enlarged | Same status as the diagrams they summarize |
| [05-onboarding-coverage](05-onboarding-coverage.mmd), [06-restore-workflow](06-restore-workflow.mmd), [07-upgrade-workflow](07-upgrade-workflow.mmd) | Operational workflows | Target; need separate qualification |

Diagrams show responsibilities, not release, capacity or qualification claims. Update the
authoritative document first, then the diagram.

## Edit and render

```bash
docs/diagrams/render.sh          # dist/*.svg, committed so the deck builds offline
PNG=1 docs/diagrams/render.sh    # also dist/*.png for chat tools (CI publishes these)
python3 docs/presentations/aws-adoption/build.py   # re-embed into the deck
```

Rendering needs Node.js and downloads a pinned `@mermaid-js/mermaid-cli` plus Chromium. SVGs use plain
SVG text (no HTML labels), which keeps them importable. `build.py` fails if
`02-logical-architecture.mmd` and the fence in `logical-architecture.md` differ or an SVG is missing.

## Use them elsewhere

- **From the deck:** click a diagram, then *Copy Mermaid*, *Download SVG* or *Download PNG*.
- **Miro, FigJam, draw.io:** these tools have Mermaid import (an app, plugin or *Insert → Mermaid*
  menu depending on product and plan). Paste the `.mmd` text. This is the editable route; check it
  in your workspace. SVG/PNG upload gives a static picture.
- **Slack:** upload the PNG (Slack does not preview SVG), or paste Mermaid in a code block or canvas.
- **Any Markdown on GitHub:** paste the file into a `mermaid` fenced block.
