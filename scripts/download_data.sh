#!/usr/bin/env bash
# Fetch public PI / jailbreak datasets to data/raw/
# Usage: bash scripts/download_data.sh
#
# All sources used here are publicly downloadable WITHOUT HuggingFace login.
# If a download fails, the script continues with what it can get.

set -uo pipefail

# Move to project root regardless of where script is invoked
cd "$(dirname "$0")/.."

mkdir -p data/raw

echo "==========================================================="
echo "PI Detector — public dataset downloader"
echo "==========================================================="

ok=0
fail=0

run_step() {
    local name="$1"; shift
    echo ""
    echo "[*] $name ..."
    if "$@"; then
        ok=$((ok + 1))
        echo "    ✓ OK"
    else
        fail=$((fail + 1))
        echo "    ✗ FAILED — continuing"
    fi
}

# 1) Lakera Gandalf-style PI (public, no auth)
run_step "Lakera/gandalf_ignore_instructions" python -c "
from datasets import load_dataset
ds = load_dataset('Lakera/gandalf_ignore_instructions', cache_dir='data/raw/lakera')
print(f'    samples: {sum(len(s) for s in ds.values())}')
"

# 2) AdvBench harmful_behaviors (raw CSV from llm-attacks repo)
run_step "AdvBench harmful_behaviors.csv" bash -c '
mkdir -p data/raw/advbench
curl -sSfL https://raw.githubusercontent.com/llm-attacks/llm-attacks/main/data/advbench/harmful_behaviors.csv \
    -o data/raw/advbench/harmful_behaviors.csv
echo "    lines: $(wc -l < data/raw/advbench/harmful_behaviors.csv)"
'

# 3) JailbreakBench (public)
run_step "JailbreakBench/JBB-Behaviors" python -c "
from datasets import load_dataset
ds = load_dataset('JailbreakBench/JBB-Behaviors', 'behaviors', cache_dir='data/raw/jbb')
print(f'    samples: {sum(len(s) for s in ds.values())}')
"

# 4) Negative samples — Databricks Dolly 15k (public, high-quality, diverse instructions)
run_step "databricks/databricks-dolly-15k (negative)" python -c "
from datasets import load_dataset
ds = load_dataset('databricks/databricks-dolly-15k', cache_dir='data/raw/dolly')
print(f'    samples: {sum(len(s) for s in ds.values())}')
"

# 5) (Optional) WildJailbreak — gated, may need huggingface-cli login
run_step "allenai/wildjailbreak (optional, may require HF login)" python -c "
from datasets import load_dataset
ds = load_dataset('allenai/wildjailbreak', 'train', cache_dir='data/raw/wildjailbreak')
print(f'    samples: {sum(len(s) for s in ds.values())}')
" || true

echo ""
echo "==========================================================="
echo "Download summary: $ok ok / $fail failed"
echo "Datasets cached in data/raw/"
echo ""
echo "Next: docker compose run --rm app python scripts/build_dataset.py"
echo "==========================================================="
