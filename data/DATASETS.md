# Datasets ledger

Rule: before a dataset is used, verify its URL, licence and filenames, download it, and record
the SHA-256 of every file here. If a URL has changed or a download fails, record that too; do
not guess. Downloads go to `data/raw/` (gitignored). Only what was verified is listed as such.

## NF-UNSW-NB15-v2 (downloaded and used for training: 2026-10-24)

| | |
|---|---|
| Landing page | https://staff.itee.uq.edu.au/marius/NIDS_datasets/ ("NetFlow V2 Datasets") |
| Host record | UQ Research Data Manager, dataset `8c6e2a00-ef9c-11ed-827d-e762de186848` (`status=PUBLISHED`, `accessType=OPEN`) |
| How it is fetched | `ml/src/download.py`: asks `https://api.rdm.uq.edu.au/datasets/<id>/download` for a time-limited signed S3 URL, streams it, checksums it |
| Licence (verbatim from the host) | "The use of the datasets for academic research purposes is granted in perpetuity after citing the above papers. For commercial purposes, it should be agreed upon by the authors. Please get in touch with the author Mohanad Sarhan for more details." |
| Citation | Sarhan, Layeghy, Portmann. *Towards a Standard Feature Set for Network Intrusion Detection System Datasets.* Mobile Networks and Applications, 2022. https://doi.org/10.1007/s11036-021-01843-0 |

| File | Bytes | SHA-256 |
|---|---:|---|
| `nf-unsw-nb15-v2.zip` | 33,877,423 | `0e42c11dc9799a1e0851ff0b98c2ed1b47c56331a6eb99ba14c800cfe94d03ed` |
| `.../data/NF-UNSW-NB15-v2.csv` | 441,867,785 | `05019e3ac8d55b3f074f9f042623bbbb1af2527b8b78558c69353ccb2ccefa3f` |
| `.../data/NetFlow_v2_Features.csv` | 2,115 | `f20e86a939f9eb53b06ace15de4cc977ed61c02e538c6465efe72b635448e939` |

The archive's other files are listed with checksums in `data/raw/nf-unsw-nb15-v2/MANIFEST.json`
(written by the downloader).

**Checked against the real file (not assumed):**

- 2,390,275 flows, identical to the host's published count; per-class counts also match the
  host's table exactly (Benign 2,295,222; Exploits 31,551; Fuzzers 22,310; Generic 16,560;
  Reconnaissance 12,779; DoS 5,794; Analysis 2,299; Backdoor 2,169; Shellcode 1,427; Worms 164).
- The raw column names used by `ml/src/features.py` (`CANONICAL_TO_RAW`) match the CSV header
  exactly. The 43 features plus `Label` and `Attack` are all present, no missing values.
- **No timestamp column**: a time-aware split is impossible; the split is random and stratified.
- Flows are **bidirectional** (IN and OUT counters both populated), hence the pairing step in the
  collector (ADR-015).
- **Exact duplicates are common**: 424,336 of 2,390,275 rows (17.8%) share every model input and
  the label with another row. Per class: Backdoor 67.5%, WebAttack ("Analysis") 69.3%,
  DoS 30.8%, Exploit/Other 24.0%, Benign 17.5%, Recon 13.8%. They were removed before splitting,
  leaving only 705 distinct Backdoor and 706 distinct WebAttack flows, which limits what any model can
  learn for those classes.
- The label mapping to the project taxonomy is in `ml/src/preprocess.py` (`ATTACK_TO_CLASS`).
  BruteForce has no examples in this dataset.

## NF-CSE-CIC-IDS2018-v2 (downloaded and used for training: 2026-10-24)

| | |
|---|---|
| Landing page | https://staff.itee.uq.edu.au/marius/NIDS_datasets/ ("NetFlow V2 Datasets") |
| Host record | UQ Research Data Manager, dataset `ce5161d0-ef9c-11ed-827d-e762de186848`, fetched exactly like the UNSW one (`ml/src/download.py`) |
| Licence | The same host text as above: academic research use granted after citing the paper; commercial use to be agreed with the authors (verbatim in `MANIFEST.json`) |
| Citation | Same paper as NF-UNSW-NB15-v2 |

| File | Bytes | SHA-256 |
|---|---:|---|
| `nf-cse-cic-ids2018-v2.zip` | 612,059,380 | `ad6307995d08ff8825d0193d5a1cfa61cf3dc4c6f223962ba3762a7775b5dc24` |
| `.../data/NF-CSE-CIC-IDS2018-v2.csv` | 3,221,378,977 | `16a545a3e139b2e85d08b1b7d9d40328c3689a49d0deaafce6dcf8d7b63e1257` |
| `.../data/NetFlow_v2_Features.csv` | 2,115 | `f20e86a939f9eb53b06ace15de4cc977ed61c02e538c6465efe72b635448e939` |

**Integrity.** The archive is a BagIt bag. The CSV's SHA-1 `80ff7fd07e2bc31164197f07fe9d9606ee565f9a`
matches the publisher's `manifest-sha1.txt`, and the zip CRC-32 of every member matches. **A first
extraction reported a CRC mismatch on the CSV; a re-download and re-extraction verified. I could not
reproduce or explain the failure** (this machine produced other unexplained transient faults the same
day). The downloader now accepts a file only if the zip CRC *or* the publisher's SHA-1 matches.

**Checked against the real file (not assumed):**

- 18,893,708 flows: 16,635,567 benign and 2,258,141 attack (counted in one pass over the whole CSV).
  Attack rows by the dataset's own label: DDOS attack-HOIC 1,080,858; DoS attacks-Hulk 432,648;
  DDoS attacks-LOIC-HTTP 307,300; Bot 143,097; Infilteration (sic) 116,361; SSH-Bruteforce 94,979;
  DoS attacks-GoldenEye 27,723; FTP-BruteForce 25,933; DoS attacks-SlowHTTPTest 14,116;
  DoS attacks-Slowloris 9,512; Brute Force -Web 2,143; DDOS attack-LOIC-UDP 2,112;
  Brute Force -XSS 927; SQL Injection 432.
- The mapping to the project taxonomy follows the host's own grouping (`cse_cic_class` in
  `ml/src/preprocess.py`): SSH + FTP brute force = 120,912 "BruteForce"; Brute Force -Web, -XSS and
  SQL Injection = 3,502 "WebAttack"; both sums match the host's published table. `map_labels` fails
  loudly on a label it does not know or when `Label` and `Attack` disagree.
- **Training reads a subset**: every attack row and 8% of benign rows (3,587,089 rows), to fit
  memory. Within that subset 445,386 rows (12.4%) are exact duplicates (same inputs and label) and
  were removed; Botnet is 81.9% duplicates, leaving 25,956 distinct Bot flows.
- **No timestamp column** and **bidirectional flows**, as for UNSW: random stratified split.

## Flow-duration artefact in both NF-*-v2 datasets (measured 2026-10-24)

`FLOW_DURATION_MILLISECONDS` holds values just under 2^32/1000 = 4,294,967 ms (the unsigned 32-bit
wrap of a negative duration: 2^32/1000 minus a median of 16 to 27 ms). Share of flows with a value
>= 4,290,000 ms, counted over the whole CSVs:

| Dataset | Benign | Attack |
|---|---:|---:|
| NF-UNSW-NB15-v2 | 5.8% (134,195 of 2,295,222) | 10.5% (10,009 of 95,053) |
| NF-CSE-CIC-IDS2018-v2 | 4.0% (660,900 of 16,635,567) | **82.6%** (1,864,677 of 2,258,141) |

In CSE-CIC the value is a near-perfect attack marker, which is a property of that testbed's flow
exporter and not of attacks; no real router exports it. Models trained on the raw value learn it
(ADR-024). The shared feature module now maps such values to 0 (`WRAPPED_DURATION_MS`), and model
cards record `feature_spec_version` so older artifacts are refused rather than served with different
inputs.

## MITRE ATT&CK Enterprise (downloaded: 2026-10-24)

| | |
|---|---|
| Source | https://github.com/mitre-attack/attack-stix-data, `enterprise-attack/enterprise-attack.json` (raw.githubusercontent.com, `master`) |
| Version | ATT&CK 20.0 (from the bundle's `x-mitre-collection`) |
| Bytes / SHA-256 | 55,271,014 / `81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352` |
| Used for | `backend/app/services/prescriptive/mappings/mitre.yaml`, generated by `sync_mitre.py`, which fails if a rule cites a mitigation id absent from this file (all 14 cited ids were found) |
| Licence | MITRE's ATT&CK terms of use apply; **not reviewed here**, confirm before redistributing |

## Not downloaded (planned in the project plan, URLs NOT verified)

NF-ToN-IoT-v2, NF-BoT-IoT-v2, NF-UQ-NIDS-v2 (same UQ page, same host and download mechanism as
above, so `download.py` can fetch them once their host ids are added);
CIC-IDS2017 (corrected labels), CSE-CIC-IDS2018, UNSW-NB15, CISA KEV, NVD, EPSS, abuse.ch feeds.

## Not datasets: reference mappings written by hand

`mappings/cis.yaml` (CIS Controls v8) and `mappings/nist.yaml` (NIST CSF 2.0) were written from the
author's knowledge, not generated from the official documents, and are marked
`status: unverified-needs-review`. They must be checked against the official texts (and by a
security expert or supervisor) before being presented as validated.

## Derived and synthetic data

- `data/samples/synthetic_flows.csv`: 705 SYNTHETIC flows made by `ml/src/synth_sample.py`
  (seed 20261024). Not real traffic; used by tests and the placeholder-era demo.
- `data/samples/sensor_demo.pcap`: SYNTHETIC packet headers (a small office for eight minutes plus a 50-port
  scan) made by `scripts/make_sensor_demo_pcap.py` (seed 2026; a test checks the committed file matches the
  script). 8,535 packets, 30 MB described, 682 kB on disk because only headers are stored. For trying the
  sensor without capture rights; nothing in it was recorded from a real network.
- `data/processed/demo_sample.csv` (gitignored, made by `make sample`): 2,962 real flows drawn
  from the held-out TEST split of NF-UNSW-NB15-v2, enriched with attacks for demonstration. It is a
  subset of a licensed dataset, so it is generated locally and never committed.
