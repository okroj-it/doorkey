#!/usr/bin/env bash
# Build the image locally and push it to GHCR, tagged with the commit it came
# from. The tag is the whole point: "which build is guarding the front door"
# has to have an answer, so a dirty tree is refused rather than tagged with a
# sha that does not describe it.
set -euo pipefail

cd "$(dirname "$0")/.."

# ghcr.io/<owner>/<repo> of the GitHub remote, unless DOORKEY_IMAGE says otherwise.
remote_image() {
  local url
  url="$(git remote get-url origin 2>/dev/null)" || return 1
  [[ "$url" =~ github\.com[:/]([^/]+)/([^/.]+) ]] || return 1
  echo "ghcr.io/${BASH_REMATCH[1],,}/${BASH_REMATCH[2],,}"
}
IMAGE="${DOORKEY_IMAGE:-$(remote_image)}" \
  || { echo "set DOORKEY_IMAGE, e.g. ghcr.io/you/doorkey (no GitHub remote to derive it from)" >&2; exit 1; }

if [[ -n "$(git status --porcelain)" ]]; then
  echo "working tree is dirty — commit first, so the tag means something" >&2
  git status --short >&2
  exit 1
fi

SHA="$(git rev-parse --short=12 HEAD)"
echo "building ${IMAGE}:${SHA}"

docker build --platform linux/amd64 -t "${IMAGE}:${SHA}" -t "${IMAGE}:latest" .
docker push "${IMAGE}:${SHA}"
docker push "${IMAGE}:latest"

echo
echo "pushed ${IMAGE}:${SHA}"
echo "pin it in your deployment:"
echo "    image: ${IMAGE}:${SHA}"
