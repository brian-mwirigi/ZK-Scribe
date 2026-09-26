# CRediT mapping

ZK-Scribe uses the fourteen roles in ANSI/NISO Z39.104-2022. The agent does not try to prove the whole taxonomy. It proves the part that happens at the keyboard, and it keeps a signed ledger for the rest.

| Role | Feasibility | Binding when the evidence qualifies |
| --- | --- | --- |
| Writing – original draft | high | `process-proven` |
| Writing – review & editing | high | `process-proven` |
| Software | moderate | `typed-artifact` |
| Formal analysis | moderate | `typed-artifact` |
| Data curation | moderate | `typed-artifact` |
| Visualization | moderate | `typed-artifact` |
| Conceptualization | unobserved | `signed-assertion` |
| Methodology | unobserved | `signed-assertion` |
| Investigation | unobserved | `signed-assertion` |
| Validation | unobserved | `signed-assertion` |
| Supervision | unobserved | `signed-assertion` |
| Project administration | unobserved | `signed-assertion` |
| Resources | unobserved | `signed-assertion` |
| Funding acquisition | unobserved | `signed-assertion` |

High means the role is the writing process itself. The composition proof is direct evidence for that role, still limited to the digital drafting session.

Moderate means the agent can show that a person typed the code, script, metadata, or caption. It cannot show that the program runs, the analysis is correct, the dataset was curated on a cluster, or the figure matches the result.

Unobserved means the contribution happens off the manuscript session: ideas, lab work, replication, mentorship, administration, materials, and money. Authors can sign a sentence that states the claim. The attestation's feasibility field stays `unobserved`, and `verify --require process` rejects it.

Passing a writing role with only `--assert` is refused. Passing funding acquisition with only a session log is refused. The two kinds of evidence are not interchangeable.
