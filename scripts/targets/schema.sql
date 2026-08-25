-- Target registry: the enrichable half of target identity.
--
-- Identity is mechanical (see seed_targets.py): the stamped target_id for an
-- unknown hostname is always its PSL registrable domain, computed in code at
-- observation generation. These tables carry (a) the curated exceptions to
-- that rule and (b) everything humans learn about a target over time.
-- Enrichment therefore never requires re-stamping observations: editing
-- `targets` changes only metadata, and a new `target_hostnames` row affects
-- only observations generated after it is loaded into the workers.
--
-- Both tables are ReplacingMergeTree keyed on the natural key with
-- `updated_at` as the version: to update a row, INSERT it again with a newer
-- updated_at. Read with FINAL (they are tiny), e.g.
--   SELECT * FROM targets FINAL WHERE target_id = 'telegram/web'
-- History is retained until merges collapse it; use `source` and `notes` to
-- record why a row changed.

CREATE TABLE IF NOT EXISTS targets
(
    -- Either '<service_slug>/<role>' (curated: facebook/website,
    -- facebook/cdn, google_dns/resolver) or a bare '<registrable-domain>'
    -- (mechanical, meaning "role not yet curated"). Stable name, never an
    -- address; renaming one is a series break, so treat ids as permanent
    -- (deprecate-and-add instead).
    target_id String,
    -- Grouping slug for "is X blocked?" questions (facebook, google, tor...).
    -- Empty means not yet curated. Safe to change at any time: it is resolved
    -- at query time, never stamped.
    service LowCardinality(String) DEFAULT '',
    -- What the target is for its service: website, cdn, api, resolver,
    -- shortener, ... Query-time metadata like `service`; the curated ids
    -- spell it, bare-domain ids leave it '' until enriched.
    role LowCardinality(String) DEFAULT '',
    -- any_of: redundant pool, blocked only if every member fails.
    -- all_of: independently required, degraded if it fails.
    combination_rule LowCardinality(String) DEFAULT 'any_of',
    -- Citizenlab category code of the dominant member URL ('' if unknown).
    category_code LowCardinality(String) DEFAULT '',
    description String DEFAULT '',
    notes String DEFAULT '',
    -- Open-ended enrichment without schema migrations (e.g. 'org' -> 'Meta',
    -- 'wikidata_id' -> 'Q355'). Promote a key to a real column when queries
    -- start depending on it.
    metadata Map(LowCardinality(String), String) DEFAULT map(),
    -- Where the row came from: 'nettest', 'curated', 'citizenlab', 'census'.
    source LowCardinality(String) DEFAULT '',
    updated_at DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (target_id);

CREATE TABLE IF NOT EXISTS target_hostnames
(
    -- Resolution order: 'exact' (hostname), 'pattern' (regex), 'ip' (literal
    -- address; how telegram DCs and public resolvers stay named), 'domain'
    -- (longest-suffix match -- catches every hostname under a curated
    -- service, seen or not, so curated identity can't diverge from the
    -- fallback; a suffix walk rather than the PSL registrable domain, since
    -- private-section suffixes like googleapis.com would otherwise hide
    -- their subdomains from the map).
    -- Only curated exceptions live here; the in-code eTLD+1 fallback covers
    -- everything else.
    matcher_kind LowCardinality(String),
    matcher String,
    target_id String,
    source LowCardinality(String) DEFAULT '',
    notes String DEFAULT '',
    -- Set 0 to retire a mapping without deleting its history.
    is_active UInt8 DEFAULT 1,
    updated_at DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (matcher_kind, matcher);
