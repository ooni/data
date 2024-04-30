
FROM apache/superset
USER root
RUN pip install clickhouse-connect

RUN mkdir -p /var/run/superset/ && chown superset:superset /var/run/superset/
COPY --chown=superset --chmod=755 ./docker/run-server-with-setup.sh /usr/bin/

USER superset
CMD ["/usr/bin/env", "bash", "/usr/bin/run-server-with-setup.sh"]