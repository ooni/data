import time
from clickhouse_driver import Client


def get_count(client) -> int:
    res = client.execute("SELECT COUNT(DISTINCT measurement_uid) FROM obs_web;")
    return int(res[0][0])


def main():
    click_client = Client.from_url("clickhouse://localhost/")
    samples = []
    last_count = get_count(click_client)
    while True:
        cur_count = get_count(click_client)
        delta = cur_count - last_count
        samples.append(delta)
        print(f"average speed: {sum(samples)/(len(samples)*2)}")
        if len(samples) > 10:
            samples = samples[-10:]
        last_count = cur_count
        time.sleep(2.0)


if __name__ == "__main__":
    main()
