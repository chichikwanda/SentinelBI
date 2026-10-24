# Datasets ledger

**No dataset has been downloaded or verified yet** (Phase 2). Nothing in this repository was
trained or evaluated on real data, and no result in the codebase comes from a real dataset.

Rule: before a dataset is used, verify its URL, licence and filenames, download it, and record
the SHA-256 of every file here. If a URL has changed or a download fails, record that too; do not
guess.

| Dataset | Planned source (from the project plan, NOT yet verified) | Licence | Files + SHA-256 | Status |
|---|---|---|---|---|
| NF-UNSW-NB15-v2, NF-CSE-CIC-IDS2018-v2, NF-ToN-IoT-v2, NF-BoT-IoT-v2, NF-UQ-NIDS-v2 | https://staff.itee.uq.edu.au/marius/NIDS_datasets/ | tbc | tbc | not downloaded |
| CIC-IDS2017 (corrected labels, Engelen et al. 2021) | https://www.unb.ca/cic/datasets/ids-2017.html | tbc | tbc | not downloaded |
| CSE-CIC-IDS2018 | https://registry.opendata.aws/cse-cic-ids2018/ | tbc | tbc | not downloaded |
| UNSW-NB15 | https://research.unsw.edu.au/projects/unsw-nb15-dataset | tbc | tbc | not downloaded |

## Synthetic sample (in the repo)

`data/samples/synthetic_flows.csv`: 705 flows (600 benign, 80 SYN-scan, 25 UDP-flood), generated
deterministically (seed 20261024) by `ml/src/synth_sample.py`. Not real traffic. A test fails if
the committed file stops matching the generator. Use it for demos and pipeline tests only.

## Known open items before the datasets are used

- The raw column names in `ml/src/features.py` (`CANONICAL_TO_RAW`) follow the NF-v2 naming from
  the plan and must be checked against the real CSV headers.
- NF-v2 flows are bidirectional; router NetFlow v5/v9 records are unidirectional (ADR-015).
