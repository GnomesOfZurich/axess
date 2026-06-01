# axess-events

[![Version](https://raw.githubusercontent.com/GnomesOfZurich/axess/main/.github/badges/version.svg)](https://crates.io/crates/axess-events)
[![Status](https://raw.githubusercontent.com/GnomesOfZurich/axess/main/.github/badges/status.svg)](https://github.com/GnomesOfZurich/axess)
[![License](https://raw.githubusercontent.com/GnomesOfZurich/axess/main/.github/badges/license.svg)](https://github.com/GnomesOfZurich/axess#licence)

[crates.io](https://crates.io/crates/axess-events) · [docs.rs](https://docs.rs/axess-events) · [Book](https://gnomesofzurich.github.io/axess/) · [GitHub](https://github.com/GnomesOfZurich/axess)

Shared event vocabulary for the [Axess](https://github.com/GnomesOfZurich/axess) workspace and adjacent domains.

The `Event<P>` envelope carries cross-cutting metadata (id, time, tenant, kind, subject, actor, trace context, status) while leaving the payload type-parameterised per domain. `EventSink<P>` is the trait every producer rides; concrete sinks include a no-op default and a `LogAndSwallow` wrapper for fail-soft dispatch.

The wire format is [rkyv](https://crates.io/crates/rkyv) for zero-copy deserialisation and schema-evolution-aware archival; designed for streaming pipelines (Apache Iggy / Kafka) feeding columnar analytical stores (ClickHouse / DuckDB / Snowflake).

## Usage

axess-events is consumed transparently by `axess-core` and by adopter analytics pipelines; see [`docs/audit-pipeline.md`](https://github.com/GnomesOfZurich/axess/blob/main/docs/audit-pipeline.md) for the integration shape.

## Licence

Dual-licensed under [MIT](https://github.com/GnomesOfZurich/axess/blob/main/LICENSE-MIT) and [Apache-2.0](https://github.com/GnomesOfZurich/axess/blob/main/LICENSE-APACHE).
