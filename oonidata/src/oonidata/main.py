import multiprocessing as mp
from oonidata.cli import cli

if __name__ == "__main__":
    # Use spawn to avoid race condition that leads to deadlocks on unix
    # See: https://bugs.python.org/issue6721
    mp.set_start_method("spawn")

    cli()
