# Cyber Thunder UI

React 18 + TypeScript + Vite + Mantine 7. Spec: `docs/UI.md`; API shapes: `docs/API.md` (mirrored in
`src/api/types.ts`). The built bundle in `dist/` is committed and served by `cyberthunder serve` from `/`,
so the operator UI works fully offline: no CDN, no web fonts (system font stacks), no telemetry.

## Prerequisites
Node 20+ (tested with Node 26 / npm 11). On the team Windows boxes Node is not on PATH in Git Bash:

```bash
export PATH="/c/Program Files/nodejs:$PATH"
```

## Develop (hot reload against the real API)

```bash
cd cyberthunder/ui
npm ci
```

```bash
python -m cyberthunder serve --port 8000
```

```bash
npm run dev
```

Open the URL Vite prints (http://localhost:5173). `vite.config.ts` proxies `/api` to `http://127.0.0.1:8000`,
including the `/api/v1/audit/stream` SSE connection.

## Rebuild the committed bundle

```bash
cd cyberthunder/ui
npm run build
```

`npm run build` runs `tsc -b` (must be zero errors) then `vite build` into `dist/` with relative asset paths
(`base: './'`). Commit `dist/` with the source change. Never hand-edit `dist/`. `node_modules/` is ignored;
`package-lock.json` is committed so `npm ci` is reproducible (and can be run from an offline npm cache).

Smoke test the bundle as the fleet will run it:

```bash
CT_STATE_DIR="$(mktemp -d)" python -m cyberthunder serve --port 8765
```

```bash
curl -s http://127.0.0.1:8765/ | head -5 && curl -s http://127.0.0.1:8765/api/v1/status
```

## Layout

```
src/main.tsx            providers: Mantine (dark navy default), notifications, app state, HashRouter
src/App.tsx             routes
src/theme.ts            navy palette, system fonts
src/app.css             "nothing animates except progress"
src/api/client.ts       typed fetch wrapper (base /api/v1, X-Actor header, ApiError{status, detail}), SSE helper
src/api/types.ts        API shapes
src/state/AppState.tsx  status poll, chain verify, actor, ONE shared audit SSE connection (useAuditListener)
src/lib/                formatting (severity colours, CAT labels, citation links), hooks (useAsync, useInterval, useLocalPref)
src/components/         Shell, KillSwitch, HeaderBadges (Chain/Link/Model), ActorChip, ProposalCard, ApplyTimeline,
                        FindingDrawer, FixPanel, CitationChips, ConfirmReasonModal, TargetForm, DiscoveryPanel,
                        IngestPanel, LinkControls, PolicyEditor, common (badges, hashes, loading/empty/error)
src/pages/              Decisions, Findings, Assets, Scans, Audit, Reports, Settings, Commander
```

## Behaviour notes for teammates
- Routing uses `HashRouter` (`/#/findings`) so deep links and refreshes work from the Python static mount
  without a server-side fallback route.
- Every request sends `X-Actor` from the name in the actor chip (localStorage key `ct.actor`). Mutations
  without a name are refused by the API with a 400 and the detail is shown verbatim.
- Live updates: one EventSource on `/audit/stream` (started after the current head, reconnects with
  backoff from the last seen seq). Each event refreshes the chain badge and status. Decisions reloads on
  `proposal.*` events and polls applying proposals every second; Scans polls while a run is pending/running.
- Apply timeline (ProposalCard): built from audit records whose subject is the proposal
  (`proposal.applying` = scope check passed, any `*before*`/`*snapshot*` action or `before_state_ref` =
  before-state captured, `proposal.applied`, `proposal.verified`, `proposal.failed`, `proposal.rolled_back`,
  `action.blocked`) with the proposal history as fallback for timestamps.
- Keyboard on Decisions: `j`/`k` move, `a` approve, `d` deny (note modal), `enter` finding detail, `x` select.
- Findings are paged 200 at a time server-side (limit/offset) instead of virtualizing.
- Discovery (Assets page, `components/DiscoveryPanel.tsx`): scopes bar (`PUT /discovery/scopes` with a
  reason), Run sweep with a mode select (polls `/discovery/runs/{id}`), a candidate table with
  new/known/changed/missing badges and expandable evidence, Accept (name, type, transport, an explicit
  in/out of scope choice with no default, required reason) and Ignore (required reason), and a Findings tab
  from `/discovery/findings`. Assets from a simulated sweep can only be accepted with transport `simulated`.
- Diff: proposals that are applied, verified, failed or rolled back show a Diff button (proposal card and the
  finding drawer's proposal history) that renders `GET /proposals/{id}/diff`. Applied runbook proposals show
  Verify (`POST /proposals/{id}/verify`).
- Findings Source filter lists the sources present in the current scan, not a fixed list.
- `tests/ui` checks that every import resolves to a tracked file, every client call names a server route,
  and dist/index.html points at built assets. Rebuild dist with every source change.
- Scope toggle: the API has no reason field on `PUT /targets/{id}`, so the required reason is appended to the
  target's `notes` in the same request; the change itself is audited as `scope.change`.
- Audit download builds `audit.jsonl` client-side from paged `GET /audit` (there is no download route).
