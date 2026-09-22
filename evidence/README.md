# Public evidence and provenance

The two CSV files were supplied with the original project. They are preserved without changing their contents. Their visible values were checked against the selected screenshots; they are reporting summaries, not original Windows log exports.

| File | Status and interpretation |
| --- | --- |
| `auth-events-summary.csv` | Six records; UTC time, record IDs, event IDs, target account, logon types, and derived diagnostic codes match image `10-evidence-hashes-and-record-ids.png`. Singapore time is UTC+08:00. The original parser's `StatusCode` preferred SubStatus, so this is not necessarily raw Status. |
| `evidence-hashes-summary.csv` | The two EVTX filenames, SHA-256 strings, and sizes match that image. Filename-derived local time is labelled as such; full collection UTC is not readable. Host and collector reflect the lab context and visible command, not an independently supplied raw manifest. |

Raw EVTXs, the complete original parser CSV, and the original hash manifest were **not supplied for this review**. Their current existence and integrity cannot be verified here. A screenshot of a hash does not replace recomputing the hash from the file.

The lab aliases `soc-test`, `SOC`, and `WIN11-SOC-LAB` are retained to make the case understandable. Blank cells mean the summary does not provide a value; they must not be filled with guessed information.

## Next collection

Keep raw logs, parser exports, audit backups, and complete hash manifests private. The revised scripts generate these under `C:\Lab\Evidence` in private subdirectories; they do not automatically anonymize data. Review selected copies before publication. Do not upload full logs, VM disks, snapshots, credentials, personal account details, or unrelated device information.

The repository's ignore rules reduce accidental additions, but they do not sanitize a file or remove anything already tracked. Use the screenshot checklist and inspect the exact staged files before publishing.

For traceability, retain a private collection note with: purpose, source host, time zone and time source, collection start/end in UTC, commands/script revision, collector, filenames, file sizes, hashes, storage location, any redactions, and subsequent access or transfer. No formal chain of custody is claimed for this portfolio exercise.
