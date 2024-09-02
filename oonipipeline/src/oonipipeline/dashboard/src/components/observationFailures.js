import { makeColorPalette } from "../lib/colorUtils.js";
import colors from "../lib/colors.js";
import { getObservationsAggregate } from "../lib/observations.js";
import * as d3 from "d3";
import * as Plot from "npm:@observablehq/plot";

const colorPalette = makeColorPalette(
  [
    "green[800]",
    "fuchsia[500]",
    "indigo[900]",
    "violet[300]",
    "yellow[500]",
    "orange[600]",
    "gray[600]",
    "pink[400]",
    "red[900]",
    "cyan[800]",
  ],
  colors
).palette;

export async function getObservationData({
  countryFilter,
  hostnameFilter,
  breakDownByIP,
}) {
  let group_by = ["timestamp", "failure"];
  if (breakDownByIP) {
    group_by.push("ip");
  }
  const obsdataByDateAgg = (
    await getObservationsAggregate({
      group_by: group_by,
      probe_cc: countryFilter,
      hostname: hostnameFilter,
      test_name: "web_connectivity",
    })
  ).aggregation;

  const obsdataByDate = obsdataByDateAgg.map((d) => ({
    ...d,
    timestamp: new Date(d.timestamp),
  }));
  const sortFailures = (prefix) => {
    return d3.groupSort(
      obsdataByDate.filter((d) => d.failure.startsWith(`${prefix}_`)),
      (D) => -d3.sum(D, (d) => d.observation_count),
      (d) => d.failure
    );
  };
  const sortedFailures = {
    dns: sortFailures("dns"),
    tcp: sortFailures("tcp"),
    tls: sortFailures("tls"),
  };
  let topFailures = ["none"];
  Object.keys(sortedFailures).forEach((key) => {
    if (sortedFailures[key].length > 3) {
      sortedFailures[key] = sortedFailures[key]
        .slice(0, 2)
        .concat(`${key}_other`);
    }
    topFailures = topFailures.concat(sortedFailures[key]);
  });

  const colorRange = colorPalette.slice(0, topFailures.length);
  const reducedObsByDate = obsdataByDate.map((d) => {
    if (topFailures.indexOf(d.failure) === -1) {
      const failureStr = `${d.failure.split("_")[0]}_other`;
      return { ...d, failure: failureStr };
    }
    return d;
  });

  return {
    colorRange,
    topFailures,
    observations: reducedObsByDate,
  };
}

export function PlotObservationFailures({
  colorRange,
  topFailures,
  breakDownByIP,
  observations,
  width,
}) {
  if (colorRange == undefined) {
    return;
  }
  if (breakDownByIP) {
    const keys = Array.from(d3.union(observations.map((d) => d.ip)));
    const fy = (key) => key;
    return Plot.plot({
      width: width,
      x: { label: null },
      y: {},
      fy: { label: null, axis: null },
      color: {
        label: "failure",
        type: "categorical",
        legend: true,
        domain: topFailures,
        range: colorRange,
      },
      marks: [
        Plot.rectY(
          observations,
          Plot.normalizeY({
            x: "timestamp",
            y: "observation_count",
            fy: "ip",
            interval: "day",
            fill: "failure",
            tip: true,
          })
        ),
        Plot.text(keys, {
          fy,
          text: (d) => d,
          frameAnchor: "top-left",
          dx: 6,
          dy: 6,
        }),
        Plot.frame(),
      ],
    });
  } else {
    return Plot.plot({
      width: width,
      x: { label: null },
      y: {},
      color: {
        label: "failure",
        type: "categorical",
        legend: true,
        domain: topFailures,
        range: colorRange,
      },
      marks: [
        Plot.rectY(observations, {
          x: "timestamp",
          y: "observation_count",
          interval: "day",
          fill: "failure",
          tip: true,
        }),
      ],
    });
  }
}
