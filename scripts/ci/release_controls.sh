#!/bin/sh
set -eu
tag=$1
tag_ref=$(gh api "repos/$GITHUB_REPOSITORY/git/ref/tags/$tag")
object_type=$(printf '%s' "$tag_ref" | jq -r '.object.type')
object_sha=$(printf '%s' "$tag_ref" | jq -r '.object.sha')
test "$object_type" = tag
test "$(gh api "repos/$GITHUB_REPOSITORY/git/tags/$object_sha" --jq '.verification.verified')" = true
git fetch origin main
git merge-base --is-ancestor "$(git rev-list -n 1 "$tag")" origin/main
python scripts/check_release_version.py "$tag"
export SOURCE_DATE_EPOCH
SOURCE_DATE_EPOCH=$(git show -s --format=%ct "$tag^{}")
build_root=$(mktemp -d)
mkdir -p "$build_root/one" "$build_root/two"
git archive HEAD | tar -x -C "$build_root/one"
git archive HEAD | tar -x -C "$build_root/two"
dist_one="$PWD/dist-one"
dist_two="$PWD/dist-two"
(cd "$build_root/one" && python -m build --outdir "$dist_one")
(cd "$build_root/two" && python -m build --outdir "$dist_two")
python scripts/ci/normalize_sdist.py dist-one/*.tar.gz "$SOURCE_DATE_EPOCH"
python scripts/ci/normalize_sdist.py dist-two/*.tar.gz "$SOURCE_DATE_EPOCH"
python -m twine check dist-one/*
mkdir -p dist
cp dist-one/* dist/
(cd dist-one && sha256sum *) > /tmp/one.sha256
(cd dist-two && sha256sum *) > /tmp/two.sha256
diff /tmp/one.sha256 /tmp/two.sha256
pip-audit -r requirements.txt --format cyclonedx-json --output dist/dusk.cdx.json
docker run --rm -v "$PWD:/src" \
  anchore/syft@sha256:b8c170b8e51bfc4779ec3ef4399942c57290f5ce76a9c3af564c9d00d4946a6b \
  dir:/src -o spdx-json=/src/dist/dusk.spdx.json
(cd dist && sha256sum ./*.whl ./*.tar.gz ./*.json > SHA256SUMS && sha256sum --check SHA256SUMS)
