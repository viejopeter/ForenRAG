# ForenRAG Sanitised Study Dataset

This package contains the sanitised trial-level data supporting the aggregate results reported in the manuscript *ForenRAG: An Event-Driven Retrieval-Augmented Framework for Provenance-Oriented Post-Alert Digital Forensic Investigation*.

The study comprised 15 matched laboratory trials: five Windows adversary-emulation scenarios, each repeated three times. Trial identifiers have the form `T<repetition>-S<scenario>`.

## Files

- `timing_results.csv`: recorded intervals for the two evaluated post-alert procedures and the decomposition of the ForenRAG interval.
- `reference_review_phases.csv`: six sanitised reference-review phase durations for each trial; absolute start and completion timestamps are excluded.
- `collector_validation.csv`: trial-level recovery, extra-association, and trigger-to-root lineage-validation counts.
- `report_grounding_summary.csv`: trial-level aggregate results from the AI-assisted, author-reviewed assessment of the 15 ForenRAG reports.
- `major_error_categories.csv`: trial-level counts for the six consolidated major-error categories reported in the manuscript.
- `retrieval_summary.csv`: trial-level passage counts, analysis-technique alignment, and retrieved source filenames.

The package intentionally excludes raw OpenSearch exports, evidence packages, complete reports, exact event timestamps, host and user identifiers, process identifiers and GUIDs, internal addresses, and absolute laboratory paths.

## Timing definitions

- `reference_review_seconds`: elapsed time from the analyst opening the matched structured evidence package to completing the reference report.
- `collection_seconds`: ForenRAG evidence-collection interval recorded during session finalisation.
- `retrieval_reasoning_seconds`: combined local retrieval and language-model processing interval.
- `forenrag_total_seconds`: `collection_seconds + retrieval_reasoning_seconds`.
- `paired_difference_seconds`: `reference_review_seconds - forenrag_total_seconds`.
- `recorded_interval_ratio`: `reference_review_seconds / forenrag_total_seconds`.
- `relative_difference_percent`: `100 * (reference_review_seconds - forenrag_total_seconds) / reference_review_seconds`.

The reference-review and ForenRAG measurements are defined operational intervals, not equivalent verified end-to-end outcomes. ForenRAG timing ends at generation of an initial report; subsequent human verification was not timed.

## Collector-validation definitions

Expected and recovered records were determined using the relevance rule reported in the manuscript. Extra associations are records returned by the implemented collector that were not relevant under that rule. `lineage_correct` indicates whether the trigger-to-root process lineage matched the raw-event validation result.

Overall association precision is calculated as:

`recovered expected records / (recovered expected records + extra associations)`.

## Report-grounding definitions

- `assessable_claims`: claims for which the matched evidence package permitted a verdict.
- `strict_evidence_support_percent`: `100 * supported_claims / assessable_claims`.
- `unsupported_or_contradicted_percent`: `100 * (unsupported_claims + contradicted_claims) / assessable_claims`.
- `traceability_percent`: `100 * traceable_claims / assessable_claims`.
- `completeness_percent`: `100 * expected_findings_covered / expected_findings_total`.
- `attack_metadata_consistent`: whether the report remained consistent with the supplied ATT&CK metadata and observable activity; this is not an independent technique-classification measure.
- `major_error_count`: author-verified major-error decisions in the report-level claim assessment.

Percentages in the CSV are rounded to one decimal place at report level. Manuscript-wide rates are calculated from pooled integer counts unless explicitly described as report-level means or medians.

## Reproducing principal manuscript values

From `timing_results.csv`:

- mean `reference_review_seconds`: 1,377.666667 s (reported as 1,377.7 s);
- mean `forenrag_total_seconds`: 98.738533 s (reported as 98.7 s);
- ratio of condition means: 13.952675 (reported as 13.95);
- relative difference between condition means: 92.832916% (reported as 92.83%).

From `reference_review_phases.csv`:

- alert verification: 99.4 s;
- log extraction: 230.1 s;
- process correlation: 393.2 s;
- artefact correlation: 188.1 s;
- threat-intelligence lookup: 164.4 s;
- report synthesis: 302.5 s.

From `collector_validation.csv`:

- recovered expected records: 196 of 196;
- extra associations: 11 (5 process, 0 file, and 6 registry);
- overall association precision: 196 / (196 + 11) = 94.7%;
- correct trigger-to-root lineages: 15 of 15.

From `report_grounding_summary.csv`:

- total claims: 213;
- assessable claims: 205;
- supported: 161; partially supported: 16; unsupported: 13; contradicted: 15; not assessable: 8;
- pooled strict evidence-support rate: 161 / 205 = 78.5%;
- pooled unsupported-or-contradicted rate: 28 / 205 = 13.7%;
- pooled traceability rate: 140 / 205 = 68.3%;
- mean completeness: 97.8%;
- reports consistent with supplied ATT&CK metadata: 14 of 15;
- major-error decisions: 21 (10.2% of assessable claims; mean 1.4 per report).

From `major_error_categories.csv`:

- outcome or success assertion: 8;
- interpretation or context: 4;
- process lineage or correlation: 4;
- content interpretation: 2;
- action assertion: 2;
- artefact-existence assertion: 1.

From `retrieval_summary.csv`:

- evidence packages: 15;
- retrieved passages: 45, with three passages per package;
- unique source filenames represented in the retrieved passages: 7;
- passages carrying the scenario analysis-technique metadata label: 45 of 45.

## Licence

The files in this directory are licensed under the Creative Commons Attribution 4.0 International licence. See [`LICENSE`](LICENSE) for the licence notice and attribution information. This licence applies only to the contents of `study_dataset/`.
