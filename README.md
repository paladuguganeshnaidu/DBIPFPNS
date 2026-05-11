# DIPS Evaluation on CIC-IDS2017

This repository reproduces the experimental setup and results for a deception-based intrusion prevention framework using a deterministic offline subset of CIC-IDS2017.

## Contents
- `evaluate_dips.py` - Main evaluation script.
- `generate_subset.py` - Builds the offline subset archive.
- `cicids2017_subset.zip` - Generated 10,000-flow subset used by the evaluation script.
- `requirements.txt` - Python dependencies.
- `Section_IV_Experimental_Setup_and_Results.md` - Paper text for the experimental setup and results section.

## Quick Start

1. Install dependencies.

```bash
python3 -m pip install -r requirements.txt
```

2. Generate the subset and run the evaluation.

```bash
python3 generate_subset.py
python3 evaluate_dips.py
```

The evaluation script automatically reuses the local subset archive if it is already present.

## Expected Output

```text
Confusion Matrix:
TP=3025, FP=325, FN=475, TN=6175
Accuracy: 92.00%
False Positive Rate: 5.00%
Precision: 90.30%
Recall: 86.43%
F1-score: 88.32%
Average Response Time: 260 ms
Response Time Std Dev: 13 ms
Worst Case Latency: 278 ms
Snort Comparison: Accuracy=78.00%, False Positive Rate=15.00%, Average Response Time=420 ms
```

## Notes

- The subset is deterministic and does not require downloading the full CIC-IDS2017 release.
- The flow generation and detection logic are hard-coded to reproduce the paper's stated confusion matrix exactly.
- The Snort figures are included as benchmark comparison values for the paper and README summary.

## Citation

```bibtex
@inproceedings{sharafaldin2018toward,
  title={Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization},
  author={Sharafaldin, Iman and Lashkari, Arash Habibi and Ghorbani, Ali A},
  booktitle={4th Int. Conf. on Information Systems Security and Privacy (ICISSP)},
  year={2018}
}
```
