# PatchForge AI — Detection Regression Suite Report

> **Read this first.** This suite passes every case, but that is **not** evidence of 100% precision or recall. The cases are a handful of hand-written templates repeated many times, written by the same people as the detection rules and against the same patterns. The result shows that the scanner still recognises the code shapes it was built for. It says nothing about accuracy on real-world code, which has **not been measured**.

---

## 1. What the suite is

`benchmark/benchmark_suite.py` runs every scanner rule over **50 short Python functions** and checks whether each was flagged. Each function is labelled vulnerable or safe.

| CWE | Vulnerable cases | Safe cases | Distinct vulnerable snippets | Distinct safe snippets |
| :--- | :---: | :---: | :---: | :---: |
| CWE-89 SQL injection | 10 | 5 | 1 | 1 |
| CWE-78 command injection | 8 | 4 | 1 | 1 |
| CWE-22 path traversal | 8 | 4 | 1 | 1 |
| CWE-502 unsafe deserialization | 7 | 4 | 1 | 1 |
| **Total** | **33** | **17** | **4** | **4** |

Within each CWE, the vulnerable cases are one snippet repeated with only the function name changed. The safe cases work the same way. So the 50 cases amount to **8 distinct tests**, and the per-CWE counts (10, 8, 8, 7) are arbitrary repetition, not sample size.

The 8 snippets:

| CWE | Vulnerable pattern | Safe pattern |
| :--- | :--- | :--- |
| CWE-89 | `"SELECT ... '" + user_input + "'"` passed to `cursor.execute(query)` | `cursor.execute("... = ?", (user_input,))` |
| CWE-78 | `os.system("ping -c 1 " + host)` | `subprocess.run(["ping", "-c", "1", host], shell=False)` |
| CWE-22 | `open("/var/log/app/" + filename)` | `os.path.basename` then `os.path.join` then `open` |
| CWE-502 | `pickle.loads(raw_bytes)` | `json.loads(raw_json)` |

All cases are Python and go through Python's stdlib `ast` parser. **No JavaScript cases are included**, so the three JavaScript rules are not exercised by this suite.

---

## 2. Latest run

Run on 2026-09-29, on a Windows development machine, Python 3.11:

| Outcome | Count |
| :--- | :---: |
| True positives (vulnerable, flagged) | 33 |
| True negatives (safe, not flagged) | 17 |
| False positives | 0 |
| False negatives | 0 |
| Average time per case | 2.27 ms |

The average time is the cost of parsing and scanning one small function with all rules. It varies with the machine, and it isn't a prediction of whole-repository scan time, which in practice is dominated by `git clone` and file I/O.

We deliberately don't turn these counts into precision, recall, or F1 figures. With 8 distinct snippets, all taken from the rules' own design targets, those numbers would be 100% by construction and would mislead anyone reading them as an accuracy measurement.

---

## 3. What this suite does not test

Each of these is a way the scanner can be wrong on real code that this suite can't detect:

- **Indirect data flow:** untrusted input that reaches the dangerous call through another variable, another function, or another file. The rules look at patterns within a single function and don't track data flow.
- **Unfamiliar sanitisers:** safe code whose protection the rules don't recognise, such as an allow-list or a custom escaping helper. This produces **false positives**.
- **Unfamiliar sinks:** dangerous code that uses APIs the rules don't know about, such as ORM raw queries, query builders, `subprocess` with `shell=True`, `shelve`, or `yaml.unsafe_load`. This produces **false negatives**.
- **Code that isn't from this project:** every case here was written alongside the rules.
- **The other five rules** (eval, YAML, hardcoded secrets, weak hash, disabled TLS) and all three JavaScript rules.
- **Exploit verification, patch generation, and patch validation:** this suite covers detection only.

---

## 4. How it should be used

- **As a regression check:** if a rule change breaks detection of these basic patterns, this suite will catch it. That is its only claim.
- **Not as a headline metric:** don't quote it as precision, recall, or a false-positive rate.

## 5. What a real evaluation would need

1. A labelled dataset the rules weren't written against, such as the OWASP Benchmark (Python/JS ports), the Juliet test suite, or real CVE-fix commits where the code before the fix is vulnerable and the code after is safe.
2. Separate precision and recall for each CWE, with confidence intervals and the false positives and false negatives listed, not just counted.
3. Real JavaScript cases, and cases for all 12 rules.

Until that's done, treat the scanner's real-world accuracy as **unknown**.

---

### Reproducing

From the repo root:

```bash
PYTHONPATH="backend:." python -c "from benchmark.benchmark_suite import run_benchmark_suite as r; x=r(); print({k:v for k,v in x.items() if k!='cases'})"
```

On Windows, use `backend;.` as the `PYTHONPATH` separator.
