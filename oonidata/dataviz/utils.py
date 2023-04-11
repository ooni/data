from clickhouse_driver import Client as Clickhouse


def click_query(q, **kw):
    click = Clickhouse("localhost")
    return click.query_dataframe(q, params=kw)
