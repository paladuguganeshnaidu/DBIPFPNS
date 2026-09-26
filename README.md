# Deceptive Intrusion Prevention System (DIPS)

Research implementation and evaluation code for a deception-based intrusion-prevention concept combining conventional detection/response with honeypot-oriented deception in a controlled network lab.

> **Research/demo scope:** run the emulation only in an isolated lab or against systems you are explicitly authorized to test.

## Repository

https://github.com/paladuguganeshnaidu/DBIPFPNS

## Components

| File | Purpose |
|---|---|
| `topo_dips.py` | Mininet topology definition for the virtual network |
| `legit_traffic.py` | Benign background traffic generator |
| `attack_sequence.sh` | Controlled lab attack-simulation sequence |
| `evaluate_dips.py` | Evaluation script for reported metrics |
| `generate_subset.py` | Generates the local labelled evaluation subset |
| `cicids2017_subset.zip` | Local subset archive |

## Requirements

The repository uses Python packages including NumPy, pandas, requests, scikit-learn, Scapy and PyShark.

The lab workflow also refers to external tools/services such as Mininet, Snort, TShark, Cowrie and Dionaea.

Example Debian/Kali setup:

```bash
sudo apt update
sudo apt install mininet python3-pip snort tshark cowrie dionaea -y
pip3 install -r requirements.txt
```

The exact package availability and service names vary by distribution.

## Quick start

Clone:

```bash
git clone https://github.com/paladuguganeshnaidu/DBIPFPNS.git
cd DBIPFPNS
```

Generate the evaluation subset:

```bash
python3 generate_subset.py
```

Run the evaluation script:

```bash
python3 evaluate_dips.py
```

## Controlled network emulation

The repository documents a Mininet workflow:

```bash
sudo mn --custom topo_dips.py --topo dips --controller=none
```

Benign traffic example:

```bash
python3 legit_traffic.py --target 10.0.0.30 --duration 60
```

The repository also contains an attack-simulation script. Use that only inside the intended isolated lab and only against authorized targets.

## Dataset

The project documents use of a pre-processed subset of CIC-IDS2017. The upstream dataset is maintained by the Canadian Institute for Cybersecurity.

Official dataset page:

https://www.unb.ca/cic/datasets/ids-2017.html

The local README states a 10,000-flow subset with 6,500 benign and 3,500 malicious flows. Treat those figures as the repository's current dataset composition, not as properties of CIC-IDS2017 as a whole.

## Reported evaluation figures

The repository's existing evaluation documentation reports:

```text
Accuracy: 92.00%
False Positive Rate: 5.00%
Precision: 90.30%
Recall: 86.43%
F1-score: 88.32%
Average Response Time: 260 ms
```

These are repository-reported experiment figures. Re-run `evaluate_dips.py` before presenting them as current reproducibility results.

## Baseline

The project documentation refers to Snort as the traditional IPS baseline. The exact Snort version/configuration should be recorded with any new experiment.

## Research status

The repository contains experimental code and evaluation scaffolding. It should not be interpreted as evidence of production-grade intrusion-prevention accuracy without additional testing on held-out data, different network conditions and an explicitly reproducible protocol.

## Security and ethics

- Use an isolated lab for active attack simulation.
- Do not run the scripts against public or third-party infrastructure without authorization.
- Treat packet captures, logs and discovered hosts as sensitive.
- Document experiment scope and rollback procedures.

## Testing

No maintained automated test suite or coverage percentage is claimed by this README. Experimental results should be regenerated from the repository code and recorded with dataset/version, model/configuration and environment details.

## License

This repository contains an MIT License. See [LICENSE](LICENSE).

## Citation

The repository currently includes a draft BibTeX placeholder rather than a finalized publication citation. Replace it with the final bibliographic record only after the associated paper has a stable publication/identifier.

## Author

Paladugu Ganesh Naidu
