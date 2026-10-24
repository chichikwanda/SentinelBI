# Samples

`synthetic_flows.csv` is generated, **synthetic** data for demonstrating the pipeline. It is not a
research dataset. Regenerate with:

```bash
python -m sentinelbi_ml.synth_sample --out data/samples/synthetic_flows.csv
```

Columns are NetFlow-style (the raw names in `sentinelbi_ml.features.CANONICAL_TO_RAW`) plus
`Label` / `Attack`, the generator's own ground truth. The replay tool ignores those two columns,
so ground truth never reaches the platform.
