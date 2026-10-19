# Tambal

https://security.blankonlinux.id/

1. Scan Debian DSA and fetch the fixed version of packages
2. Evaluate the packages in targeted repository (WIP)
3. Automate the update to repository (WIP)

This is part of BlankOn's responsibility as derivative distribution.

## Usage

```
python3 tambal.py --repo=http://arsip-dev.blankonlinux.id/sinambung/ --output=./advisories.json --html=./security-advisories
```

## Options

- `--repo=` / `--repository=` — target repository root (required).
- `--output=` — write the JSON findings to this file (optional).
- `--html=` — write the HTML report to this directory (optional).
- `--no-cache` — re-download the Debian security-tracker data instead of using the cached `tracker.json`.
- `--no-nvd` — skip NVD severity enrichment (faster; severity comes from Debian data only).
- `--no-dsa` — skip the DSA list fetch and hide the DSA column.
- `--min-severity=high` — only show packages at or above this severity (`critical`/`high`/`medium`/`low`).

## Image packages

`--image-packages=PATH_OR_URL` switches the scan from the archive to the set of
source packages that actually ship in an image. The manifest published next to
each ISO is enough:

```
python3 tambal.py \
  --repo=https://arsip.blankonlinux.id/sinambung/ \
  --image-packages=https://jahitan.blankonlinux.id/releases/current/blankon-sinambung-26.09-verbeek-amd64.packages \
  --output=./advisories.json --html=./security-advisories
```

Each finding gets one of three states. The JSON keys stay stable; the HTML uses
action-oriented labels:

| State (JSON) | Report label | Meaning |
|---|---|---|
| `fixable_now` | Upgrade available | The archive already contains the sid fix; `apt upgrade` resolves it. |
| `needs_sync` | Archive update needed | The archive is not yet at the sid fix, so no user-side upgrade can resolve it. |
| `no_fix` | No fix yet | The tracker has no resolved sid fix (an open or undetermined CVE); an upstream patch may still exist but is not packaged. |

`fixable_now` deliberately requires `archive >= sid fixed version`, not merely
`archive > image`: an archive that is newer but still below the fix cannot
resolve the vulnerability. Without the flag, behaviour and JSON are unchanged.

The image manifest lists binary packages, while the tracker is keyed by source
package. The binary→source map is built from the archive's `Sources` and
`Packages` indexes, so `libcurl4t64` is evaluated as `curl`.

## NVD severity

Severity (Critical / High / Medium / Low) is fetched from the NVD API and cached
in `nvd-cache.json`. By default it runs keyless (5 requests / 30s). Set an NVD API
key to raise that to 50 requests / 30s — either in the environment or in a `.env`
file next to the script:

```
NVD_API_KEY=your-key-here
```

Both `.env` and `nvd-cache.json` are gitignored.
