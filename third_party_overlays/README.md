# Third-Party Overlays (No-Upstream-Impact Workflow)

This repository treats third-party code as upstream-owned.
Local adaptations must be tracked as overlays in `privacy_agent`, not pushed to upstream third-party branches.

## Scope

Configured third-party repos are listed in:

- `third_party_overlays/manifest.json`

Current scope includes:

- `third_party/ASB`
- `third_party/DRIFT`
- `third_party/agentdojo`
- `third_party/agentleak_official`
- `third_party/agents`
- `third_party/ipiguard`
- `third_party/nanoclaw`
- `third_party/wasp`
- `integrations/openclaw` (git submodule working tree)

## CLI

Use:

```bash
python scripts/third_party_overlay_manager.py --help
```

Key commands:

1. Show status:

```bash
python scripts/third_party_overlay_manager.py status
```

2. Lock all third-party push remotes:

```bash
python scripts/third_party_overlay_manager.py lock-push
```

This writes backup URLs to:

- `third_party_overlays/remotes/push_urls.json`

3. Export local overlays as patch artifacts:

```bash
python scripts/third_party_overlay_manager.py export
```

This writes per-repo overlays under:

- `third_party_overlays/patches/<repo>/commits.patch`
- `third_party_overlays/patches/<repo>/staged.patch`
- `third_party_overlays/patches/<repo>/working.patch`
- `third_party_overlays/patches/<repo>/metadata.json`

4. Re-apply overlays:

```bash
python scripts/third_party_overlay_manager.py apply
```

5. Restore push remotes (if needed):

```bash
python scripts/third_party_overlay_manager.py unlock-push
```

## Policy

1. Do not push to upstream third-party remotes from this workspace.
2. Keep third-party deltas represented as overlay patch artifacts.
3. Commit overlay metadata/patches in `privacy_agent` when reproducibility requires it.
