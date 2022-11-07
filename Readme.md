## OONI Data

## Using this repo

To get yourself started with using this repo, run the following:

```
poetry install
mkdir output/
poetry run python oonidata/processing.py --csv-dir output/ --geoip-dir ../historical-geoip/country-asn-databases --asn-map ../historical-geoip/as-orgs/all_as_org_map.json
```

## Architecture overview

This data pipeline works by dealing with the data in two different stages:
* Observation generation
* Verdict generation

### Observation generation

The goal of the Observation generation stage is to take raw OONI measurements
as input data and produce as output observations.

An observation is a timestamped statement about some network condition that was
observed by a particular vantage point. For example, an observation could be
"the TLS handshake to 8.8.4.4:443 with SNI equal to dns.google failed with
a connection reset by peer error".

What these observations mean for the
target in question (e.g., is there blocking or is the target down?) is something
that is to be determined when looking at data in aggregate and is the
responsibility of the Verdict generation stage.

During this stage we are also going to enrich observations with metadata about
IP addresses (using the IPInfoDB) and detecting known fingerprints of
blockpages or DNS responses using the FingerprintDB.

The data flow of the observation generation pipeline looks as follows:

```mermaid
graph TD
    IPInfoDB[(IPInfoDB)] --> MsmtProcessor
    FingerprintDB[(FingerprintDB)] --> MsmtProcessor

    Msmt[Raw Measurement] --> MsmtProcessor{{"measurement_processor()"}}
    MsmtProcessor --> TCPObservations
    MsmtProcessor --> DNSObservations
    MsmtProcessor --> TLSObservations
    MsmtProcessor --> HTTPObservations
```


The `measurement_processor` stage can be run either in a streaming fashion as
measurements are uploaded to the collector or in batch mode by reprocessing
existing raw measurements.

```mermaid
graph LR
    P((Probe)) --> M{{Measurement}}
    BE --> P
    M --> PL[(Analysis)]
    PL --> O{{Observations}}
    O --> PL
    PL --> BE{{ExperimentResult}}
    BE --> E((Explorer))
    O --> E
```

### ExperimentResult generation

The data flow of the blocking event generation pipeline looks as follows:
```mermaid
classDiagram
    direction RL

    ExperimentResult --* WebsiteExperimentResult
    ExperimentResult --* WhatsAppExperimentResult

    ExperimentResult : +String measurement_uid
    ExperimentResult : +datetime timestamp
    ExperimentResult : +int probe_asn
    ExperimentResult : +String probe_cc
    ExperimentResult : +String network_type
    ExperimentResult : +struct resolver
    ExperimentResult : +List[str] observation_ids
    ExperimentResult : +List[BlockingEvent] blocking_events
    ExperimentResult : +float ok_confidence

    ExperimentResult : +bool anomaly
    ExperimentResult : +bool confirmed

    class WebsiteExperimentResult {
      +String domain_name
      +String website_name
    }

    class WhatsAppExperimentResult {
        +float web_ok_confidence
        +String web_blocking_detail

        +float registration_ok_confidence
        +String registration_blocking_detail

        +float endpoints_ok_confidence
        +String endpoints_blocking_detail
    }

    class BlockingEvent {
        blocking_type: +BlockingType
        blocking_subject: +String
        blocking_detail: +String
        blocking_meta: +json
        confidence: +float
    }

    class BlockingType {
        <<enumeration>>
        OK
        BLOCKED
        NATIONAL_BLOCK
        ISP_BLOCK
        LOCAL_BLOCK
        SERVER_SIDE_BLOCK
        DOWN
        THROTTLING
    }
```

```mermaid
graph
    M{{Measurement}} --> OGEN[[observationGen]]
    OGEN --> |many| O{{Observations}}
    O --> CGEN[[controlGen]]
    O --> ODB[(ObservationDB)]
    ODB --> CGEN
    CGEN --> |many| CTRL{{Controls}}
    CTRL --> A[[Analysis]]
    FDB[(FingerprintDB)] --> A
    NDB[(NetInfoDB)] --> A
    O --> A
    A --> |one| ER{{ExperimentResult}}
    ER --> |many| BE{{BlockingEvents}}
```

Some precautions need to be taken when running the `verdict_generator()` in
batch compared to running it in streaming mode.
The challenge is that you don't want to have to regenerate baselines that often
because it's an expensive process.

Let us first discuss the usage of the Verdict generation in the context of a
batch workflow. When in batch mode, we will take all the Observations in the desired
`time_interval` and `target`. In practice what we would do is process the data
in daily batches and apply the `GROUP BY` clause to a particular target.
It is possible to parallelise these task across multiple cores (and possibly
even across multiple nodes).

A baseline is some ground truth information about the target on that given day,
we generate this once and then apply it to all the observations for that target
from every testing session to establish the outcome of the verdict.

It's reasonable to do this over a time window of a day, because that will mean
that the baseline will be pertaining to at most 24h from the observation.

The challenge is when you want to do something similar for data as it comes in.
The problem there is that if you use data from the last day, you will end up
with a delta from the observation that can be up to 48h, which might be to much.
OTOH if you use data from the current day, you may not have enough data.
Moreover, it means that the result of the `verdict_generator` in batch mode
will differ from a run in streaming, which can lead to inconsistent results.

I think we would like to have the property of having results be as close as
possible to the batch run, while in streaming mode, and have some way of getting
eventual consistency.

The proposed solution is to generate baselines for all the targets (which is a
small set and can even be kept in memory) on a rolling 1h basis. This way
verdicts can be calculated based on a baseline that will be from a delta of at
most 24h.

Once the day is finished, we can re-run the verdict generation using the batch
workflow and mark for deletion all the verdicts generated in streaming mode, leading
to an eventual consistency.

The possible outcomes for the verdict are:

* dns.blockpage
* dns.bogon
* dns.nxdomain
* dns.{failure}
* dns.inconsistent
* tls.mitm
* tls.{failure}
* http.{failure}
* https.{failure}
* http.blockpage
* http.bodydiff
* tcp.{failure}


### Current pipeline

This section documents the current [ooni/pipeline](https://github.com/ooni/pipeline)
design.

```mermaid
graph LR

    Probes --> ProbeServices
    ProbeServices --> Fastpath
    Fastpath --> S3MiniCans
    Fastpath --> S3JSONL
    Fastpath --> FastpathClickhouse
    S3JSONL --> API
    FastpathClickhouse --> API
    API --> Explorer
```

```mermaid
classDiagram
    direction RL
    class CommonMeta{
        measurement_uid
        report_id
        input
        domain
        probe_cc
        probe_asn
        test_name
        test_start_time
        measurement_start_time
        platform
        software_name
        software_version
    }

    class Measurement{
        +Dict test_keys
    }

    class Fastpath{
        anomaly
        confirmed
        msm_failure
        blocking_general
        +Dict scores
    }
    Fastpath "1" --> "1" Measurement
    Measurement *-- CommonMeta
    Fastpath *-- CommonMeta
```
