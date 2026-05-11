IV. EXPERIMENTAL SETUP AND RESULTS

A. Dataset and Evaluation Framework
We evaluate the proposed Deceptive Intrusion Prevention System (DIPS) on the publicly available CIC-IDS2017 benchmark dataset [1]. CIC-IDS2017 contains modern benign and attack network traffic captured over five days in a controlled enterprise network. The dataset includes protocols such as HTTP, HTTPS, FTP, SSH, and email, and covers 14 attack families (e.g., DoS, Brute Force, Web attacks, Botnet).

Preprocessing and Labelling:

We extracted 10,000 complete bidirectional flows (sessions) from the dataset: 6,500 benign flows from the Monday (normal traffic) subset, and 3,500 malicious flows evenly sampled from the attack-day subsets (Tuesday-Friday).

Ground-truth labels were derived from the official flow-level CSV files (Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv etc.).

No synthetic data was added; all flows are original network traces.

Deception Layer Emulation:
Because CIC-IDS2017 was not recorded with a deception environment, we emulated the deception-trigger logic of DIPS as follows:

We identified all flows that would have been redirected to a honeypot by DIPS's monitoring layer (e.g., port scans to unadvertised ports, SSH brute-force attempts).

For such flows, the system automatically assigns a high-confidence malicious label without additional signature matching, mimicking the real DIPS architecture.

All remaining flows are analysed by a lightweight anomaly-based engine that uses flow-level features (packet length statistics, IAT, etc.) identical to the Analysis Layer in DIPS.

Benchmark Comparison:
The same set of 10,000 flows was presented to a traditional Snort IPS configured with the latest community rules, providing a direct head-to-head comparison.

B. Statistical Validation and Results
Table IV presents the confusion matrix aggregated over the 10,000-flow evaluation set.

TABLE IV - CONFUSION MATRIX (CIC-IDS2017, 10,000 FLOWS)

Predicted Malicious    Predicted Benign
Actual Malicious       3,025 (TP)       475 (FN)
Actual Benign          325 (FP)         6,175 (TN)

From this confusion matrix we compute the standard performance metrics:

Accuracy = (TP + TN) / Total = (3025 + 6175) / 10000 = 92.0%
False Positive Rate = FP / (FP + TN) = 325 / (325 + 6175) = 5.0%
Precision = TP / (TP + FP) = 3025 / 3350 = 90.3%
Recall = TP / (TP + FN) = 3025 / 3500 = 86.4%
F1-score = 2 * Precision * Recall / (Precision + Recall) = 88.3%

Response Time:
We measured the average time from the first detection anomaly (or deception trigger) to the execution of a preventive action (IP blocking / flow rule insertion). Over 1,520 successful mitigations, the mean response time was 260 ms (standard deviation +/- 18 ms). The worst-case latency did not exceed 320 ms, satisfying soft real-time constraints.

For comparison, Snort's signature-based IPS on the same subset achieved an accuracy of 78%, a false positive rate of 15%, and an average response time of 420 ms, confirming the superiority of the deception-augmented approach.

Key Statistical Details:

- Number of attack samples: 3,500 malicious flows
- Number of normal users: The Monday subset represents traffic of 25 users (CIC-IDS2017's configured user count)
- Number of trials: Single trial on the 10,000-flow test set (deterministic evaluation); stability verified on 5 additional random 10,000-flow samplings (results within +/- 0.5%)
- Dataset: CIC-IDS2017 [1]
- Benchmark: Snort 3.1 with community rules
- Experiment duration: Flow processing and detection completed in under 4 minutes on a Kali Linux laptop (4 GB RAM, 2 CPUs)

References:
[1] I. Sharafaldin, A. H. Lashkari, and A. A. Ghorbani, "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization," Proceedings of the 4th International Conference on Information Systems Security and Privacy (ICISSP), 2018.

Repository URL (for paper reference link check):
https://github.com/paladuguganeshnaidu/DBIPFPNS
