# from oonipipeline.workflows.response_archiver import ResponseArchiver
# from oonipipeline.workflows.fingerprint_hunter import fingerprint_hunter


import time


def wait_for_mutations(db, table_name):
    while True:
        res = db.execute(
            f"SELECT * FROM system.mutations WHERE is_done=0 AND table='{table_name}';"
        )
        if len(res) == 0:  # type: ignore
            break
        time.sleep(1)
