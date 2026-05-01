#!/usr/bin/env bash
export PATH="/home/jack/bin:/usr/local/bin:/usr/bin:/bin"

set -euo pipefail

STAGING_DIR="/opt/oci-logs/staging"
mkdir -p "$STAGING_DIR"
# -------- CONFIG --------
AUTH_MODE= ************
NAMESPACE= ************
BUCKET_NAME= ***********************
PREFIX= ******************************               
DEBUG="1"      

STATE_DIR="/opt/oci-logs/state"
IN_DIR="/opt/oci-logs/incoming"
SEEN_FILE="${STATE_DIR}/seen.txt"

mkdir -p "$STATE_DIR" "$IN_DIR"
touch "$SEEN_FILE"

if [[ "$DEBUG" == "1" ]]; then set -x; fi

# -------- LIST OBJECT NAMES 
mapfile -t OBJECTS < <(
  oci os object list \
    --auth "${AUTH_MODE}" \
    --namespace "${NAMESPACE}" \
    --bucket-name "${BUCKET_NAME}" \
    --prefix "${PREFIX}" \
    --all \
  | jq -r '.data[].name'
)

# -------- PROCESS EACH OBJECT 
for obj in "${OBJECTS[@]}"; do
  obj=$(echo "$obj" | tr -d "\r" | sed 's/[[:space:]]*$//' | tr -d "'")
  echo "OBJ='$obj'"
  # Only process OCI log objects we care about
  case "$obj" in
   */*.log.gz|*.log.gz|*/*.json.gz|*.json.gz|*/*.log|*.log) ;;
    *) continue ;;
  esac

  # Skip if already processed
  if grep -Fxq "$obj" "$SEEN_FILE"; then
    continue
  fi

  echo "[+] Will download: $obj"

  tmp_gz="/tmp/$(basename "$obj")"
  staged="${STAGING_DIR}/$(basename "${obj%.gz}")"
  out_file="${IN_DIR}/$(basename "${obj%.gz}")"  

  
  if ! oci os object get \
        --auth "${AUTH_MODE}" \
        --namespace "${NAMESPACE}" \
        --bucket-name "${BUCKET_NAME}" \
        --name "$obj" \
        --file "$tmp_gz" ; then
    echo "[!] ERROR: download failed: $obj"
    rm -f "$tmp_gz" || true
    continue
  fi

  # Sanity
  if file "$tmp_gz" | grep -qi 'gzip'; then
    echo "Detected gzip file, decompressing $staged"
    if ! gunzip -c "$tmp_gz" > "$staged"; then
        echo "[!] Error: gunzip failed on $tmp_gz"
        rm -f "$tmp_gz" "$staged" || true
        continue
    fi
  else
      echo "[+] not gzipped, copying as is to $staged"
      cp "$tmp_gz" "$staged"
  fi
 
  rm -f "$tmp_gz"

  mv "$staged" "$out_file"

  # Mark as processed only after successful download+gunzip
  echo "$obj" >> "$SEEN_FILE"
done
