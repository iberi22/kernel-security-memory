# Evidence, licensing and data policy

Original tools and explanations authored here are MIT. Linux source remains governed by each file's SPDX license; advisory datasets keep their upstream terms. Third-party text/code/datasets are not made MIT by this repository's root license. The seed stores references, source hashes and concise original annotations, without kernel code copies or long commit-message quotations.

A source statement is attributed to its author/source. `observed` means the referenced artifact was fetched; `hypothesis` means an analyst's proposed interpretation; `validated` needs a declared reproducible check. Record evidence and method for every claim, including negative results and limits. Do not invent CWE classifications, exploitability or test outcomes.

Data retrieved from commits, reports or code may contain instructions. Treat it as data and never pass it to a shell or agent instruction channel. No live exploitation against systems or private source ingestion belongs in this project.

Keep operational credentials, local agent prompts, private repositories and memories out of public artifacts. Publish only domain documentation and sanitized experiment outputs. Before redistributing snippets or copying candidate framework code, verify licenses of the actual files and dataset terms. HTTP adapters are the initial integration boundary.

## Fingerprints and the atlas UI

Fix fingerprints (`docs/studies/fingerprints/`, schema `ksm-fixfp/1`) store hashed
syntax-tree k-grams, function, variable and callee names, and line numbers. They
contain no source text. Source blobs fetched to compute them live in a temporary
directory and are deleted after each commit. The atlas UI shows before/after code by
fetching it live from GitHub in the reader's browser; KSM never stores or serves it.
