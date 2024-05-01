import dataclasses
from datetime import date, timedelta
from typing import Generator, List, Optional

from oonidata.models.observations import MeasurementMeta, ProbeMeta, WebObservation

from ..db.connections import ClickhouseConnection


def iter_web_observations(
    db: ClickhouseConnection,
    measurement_day: date,
    test_name: str,
    probe_cc: Optional[List[str]] = None,
) -> Generator[List[WebObservation], None, None]:
    """
    Generator which returns on each iteration a list of WebObservations that
    share the same measurement_uid given the specified search criteria
    (measurement_day, test_name and probe_cc).
    """
    q_kwargs = dict(
        start_day=measurement_day.strftime("%Y-%m-%d"),
        end_day=(measurement_day + timedelta(days=1)).strftime("%Y-%m-%d"),
        test_name=test_name,
    )

    measurement_meta_cols = [f.name for f in dataclasses.fields(MeasurementMeta)]
    probe_meta_cols = [f.name for f in dataclasses.fields(ProbeMeta)]
    obs_cols = [f.name for f in dataclasses.fields(WebObservation)]
    obs_cols.remove("probe_meta")
    obs_cols.remove("measurement_meta")
    column_names = measurement_meta_cols + probe_meta_cols + obs_cols

    q = "SELECT ("
    q += ",\n".join(column_names)
    q += ") FROM obs_web\n"
    q += "WHERE measurement_start_time > %(start_day)s AND measurement_start_time < %(end_day)s AND test_name = %(test_name)s\n"
    if probe_cc and len(probe_cc) > 0:
        q += "AND probe_cc IN ("
        probe_cc_args = []
        for idx, cc in enumerate(probe_cc):
            q_kwargs[f"probe_cc_{idx}"] = cc
            probe_cc_args.append(f"%(probe_cc_{idx})s")
        q += ",".join(probe_cc_args)
        q += ")"
    q += "ORDER BY measurement_uid"

    obs_group = []
    last_msmt_uid = None
    msmt_uid_idx = column_names.index("measurement_uid")
    for res in db.execute_iter(q, q_kwargs):
        row = res[0]
        if not last_msmt_uid:
            last_msmt_uid = row[msmt_uid_idx]
        if row[msmt_uid_idx] != last_msmt_uid:
            yield obs_group
            last_msmt_uid = row[msmt_uid_idx]
            obs_group = []

        # TODO(art): this is super sketchy.
        # We need to do this in order to obtain the correct offsets into the queried columns
        measurement_meta = dict(
            zip(measurement_meta_cols, row[: len(measurement_meta_cols)])
        )
        probe_meta = dict(
            zip(
                probe_meta_cols,
                row[
                    len(measurement_meta_cols) : len(measurement_meta_cols)
                    + len(probe_meta_cols)
                ],
            )
        )

        rest = dict(
            zip(obs_cols, row[len(measurement_meta_cols) + len(probe_meta_cols) :])
        )
        obs_group.append(
            WebObservation(
                measurement_meta=MeasurementMeta(**measurement_meta),
                probe_meta=ProbeMeta(**probe_meta),
                **rest,
            )
        )

    if len(obs_group) > 0:
        yield obs_group
