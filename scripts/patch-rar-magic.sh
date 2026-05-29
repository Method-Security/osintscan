#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -eq 0 ]]; then
  echo "usage: $0 <file-or-directory>..." >&2
  exit 2
fi

patch_file() {
  local file="$1"

  if [[ ! -f "$file" ]]; then
    return 0
  fi

  perl -0pi -e 's/Rar!\x1a\x07/Rax!\x1a\x07/g' "$file"
}

for path in "$@"; do
  if [[ -d "$path" ]]; then
    while IFS= read -r -d '' file; do
      patch_file "$file"
    done < <(find "$path" -type f -print0)
  else
    patch_file "$path"
  fi
done
