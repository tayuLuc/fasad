---
license: mit
language:
- ru
pretty_name: Russian PII NER Benchmark
size_categories:
- 1K<n<10K
task_categories:
- token-classification
tags:
- pii
- ner
- named-entity-recognition
- pii-detection
- privacy
- anonymization
- guardrails
- russian
- benchmark
---

# Russian PII NER Evaluation Dataset

## Dataset Description

This dataset is designed for evaluating **PII (Personally Identifiable
Information) detection** and **Named Entity Recognition (NER)** systems on
Russian-language text. It targets guardrail and anonymization pipelines that
must reliably find personal data (names, addresses, contacts) and Russian
identity-document numbers (passport, SNILS, INN, OMS, etc.) in text.

The test set combines real, manually annotated examples from production logs
—where all real personal data has been replaced with synthetic equivalents—along
with synthetic document-style texts and hand-filtered hard negatives. It is
token-level annotated in the standard **BIO** scheme across **21 entity types**.
We position this dataset as a  benchmark for Russian PII NER, and a
comparative evaluation of several prominent NER systems is presented below.

## Content Categories

The dataset is annotated across **21 entity types**, grouped into four families:

**1. Person (names)**
`FIRST_NAME`, `LAST_NAME`, `MIDDLE_NAME` — given name, surname, and patronymic,
including mixed-case, latin-script, and out-of-order spellings.

**2. Location / Address**
`COUNTRY`, `REGION`, `DISTRICT`, `CITY`, `STREET`, `HOUSE` — the full Russian
address hierarchy down to the house/building number.

**3. Contacts**
`EMAIL`, `PHONE`, `URL`, `IP_ADDRESS` — structured contact and network
identifiers in many real-world formats.

**4. Russian identity-document numbers**
`PASSPORT`, `INN` (taxpayer number), `SNILS` (insurance account), `OMS`
(medical insurance policy), `CREDIT_CARD`, `DRIVER_LICENSE`,
`MILITARY_ID`, `BIRTH_CERTIFICATE` — document numbers in their canonical and
noisy/typo'd forms.

## Test Sample Composition

The dataset contains **2,841 sentences** with **5,614 annotated entity spans**.

**Table 1. Entity spans per type**

| Entity | Count | Entity | Count | Entity | Count |
|--------|------:|--------|------:|--------|------:|
| FIRST_NAME | 499 | MILITARY_ID | 278 | REGION | 176 |
| PASSPORT | 494 | INN | 263 | PHONE | 173 |
| LAST_NAME | 457 | COUNTRY | 242 | STREET | 171 |
| DRIVER_LICENSE | 371 | SNILS | 223 | OMS | 170 |
| BIRTH_CERTIFICATE | 341 | EMAIL | 221 | HOUSE | 163 |
| CITY | 339 | URL | 206 | DISTRICT | 161 |
| MIDDLE_NAME | 308 | CREDIT_CARD | 203 | IP_ADDRESS | 155 |

**Table 2. Spans grouped into coarse categories** (used for cross-model comparison)

| Coarse category | Fine types | Spans |
|-----------------|-----------|------:|
| PERSON | FIRST_NAME, LAST_NAME, MIDDLE_NAME | 1,264 |
| LOCATION | COUNTRY, REGION, DISTRICT, CITY, STREET, HOUSE | 1,252 |
| RU_DOC_ID | SNILS, OMS, MILITARY_ID, BIRTH_CERTIFICATE | 1,012 |
| PASSPORT | PASSPORT | 494 |
| DRIVER_LICENSE | DRIVER_LICENSE | 371 |
| INN | INN | 263 |
| EMAIL | EMAIL | 221 |
| URL | URL | 206 |
| CREDIT_CARD | CREDIT_CARD | 203 |
| PHONE | PHONE | 173 |
| IP_ADDRESS | IP_ADDRESS | 155 |

**Data provenance.** The examples come from three kinds of sources:

- **Annotated production logs** — real user queries and messages, manually
  verified and BIO-labeled.
- **Synthetic document-style texts** — generated templates for each Russian
  document type (passport, SNILS, INN, OMS, driving licence, birth certificate,
  military ID, bank cards, mixed documents), plus number-format and typo-trigger
  variations, to stress structured-identifier detection.
- **Hard negatives** — borderline examples filtered manually.

## Data Structure

| Column | Type | Description |
|--------|------|-------------|
| `text` | string | Original sentence |
| `tokens` | string | JSON list of word tokens |
| `ner_tags` | string | JSON list of BIO tags, one per token |

The 21 labels appear in the BIO scheme as `B-<TYPE>` / `I-<TYPE>` (plus `O`),
e.g. `B-FIRST_NAME`, `I-STREET`, `B-SNILS`.

## Benchmarks

This dataset serves as a benchmark for Russian PII/NER systems. Because external
NER models do not reproduce the fine-grained Russian address split or the
document-number taxonomy, models are compared on a **coarse** schema, and the
headline ranking uses the **common scope** — `PERSON` + `LOCATION` — the
category set that every general NER model supports.

**Evaluation metric:** span-level **micro-F1**, with adjacent same-category
spans merged on both sides and **overlap** matching (a prediction counts if it
overlaps a gold span of the same category). Best decision threshold per model is
reported. Exact-match scoring is also available in the harness.

**Evaluated models.** All systems are zero-shot / general-purpose NER queried
with type prompts. For the GLiNER family, `[en]` / `[ru]` denotes the **prompt
language** (the text itself is Russian), since these models are multilingual.


### Results — common scope (PERSON + LOCATION), micro-F1 (%)

| # | Model | Type | Prompt | Best F1 |
|---|-------|------|--------|--------:|
| 1 | gliner_multi | zero-shot GLiNER | ru | 73.1 |
| 2 | gliner-guard-uniencoder | GLiNER2 guard | en | 70.1 |
| 3 | gliner_multi_pii-v1 | zero-shot GLiNER | ru | 69.9 |

Among the zero-shot GLiNER systems, Russian prompts help `gliner_multi` most. The
Russian-specific document categories (PASSPORT, INN, SNILS, OMS, etc.) are not
fully covered by these models, this leaderboard focuses only on the categories present across all evaluated models. 


## Citation

If you use this dataset, please cite this repository.
