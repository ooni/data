```js
import * as Plot from "npm:@observablehq/plot"
import colors from "./lib/colors.js"
import { makeColorPalette } from "./lib/colorUtils.js"
import { getObservationsAggregate } from "./lib/observations.js"
```

```js
const loading = Mutable(0);
const startLoading = () => loading.value++
const endLoading = () => loading.value--
```

## Data plot

Loading in progress: ${loading}

```js
startLoading()
const ccCounts = (await getObservationsAggregate({
  group_by: [
    "probe_cc"
  ],
  test_name: "web_connectivity"
})).aggregation
endLoading()
```

```js
const availableCountries = [...new Set(ccCounts.map(d => d.probe_cc))].sort()
const countryPicker = view(Inputs.select(availableCountries, {label: "Probe CC"}));
```

```js
startLoading()
const hostnameCounts = (await getObservationsAggregate({
  group_by: [
    "hostname"
  ],
  test_name: "web_connectivity",
  probe_cc: countryPicker
})).aggregation
endLoading()
```

```js
const availableHostnames = [...new Set(hostnameCounts.map(d => d.hostname))].sort()
//const hostnamePicker = view(Inputs.select(availableHostnames, {label: "Hostname"}));
```


```js
const tableSelection = view(Inputs.table(hostnameCounts, {
  required: false,
  columns: [
    "hostname",
    "observation_count",
    "probe_cc",
  ],
}));
```

```js
const breakDownByIP = view(Inputs.toggle({label: "By IP", value: false}));
```

```js
startLoading()
let hostnameFilter
let group_by = [
  "timestamp", "failure"
]
if (tableSelection.length > 0) {
  hostnameFilter = tableSelection.map(d => d.hostname)
}
if (breakDownByIP) {
  group_by.push("ip")
}
const obsdataByDateAgg = (await getObservationsAggregate({
  group_by: group_by,
  probe_cc: countryPicker,
  hostname: hostnameFilter,
  test_name: "web_connectivity",
})).aggregation
endLoading()
```

```js
const obsdataByDate = obsdataByDateAgg.map(d => ({...d, timestamp: new Date(d.timestamp)}))
const sortFailures = (prefix) => {
  return d3.groupSort(obsdataByDate.filter(d => d.failure.startsWith(`${prefix}_`)), (D) => -d3.sum(D, (d) => d.observation_count), (d) => d.failure)
}
const sortedFailures = {
  "dns": sortFailures("dns"),
  "tcp": sortFailures("tcp"),
  "tls": sortFailures("tls"),
}
let topFailures = ["none"]
Object.keys(sortedFailures).forEach(key => {
  if (sortedFailures[key].length > 3) {
    sortedFailures[key] = sortedFailures[key].slice(0, 2).concat(`${key}_other`)
  }
  topFailures = topFailures.concat(sortedFailures[key])
})

const colorPalette = makeColorPalette([
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
], colors).palette

const colorRange = colorPalette.slice(0, topFailures.length)
const reducedObsByDate = obsdataByDate.map((d) => {
  if (topFailures.indexOf(d.failure) === -1) {
    const failureStr = `${d.failure.split("_")[0]}_other`
    return {...d, failure: failureStr}
  }
  return d
})
```


```js
view(Inputs.table(reducedObsByDate));
function plotChart(width) {
  if (breakDownByIP) {
    const keys = Array.from(d3.union(reducedObsByDate.map((d) => d.ip)));
    const fy = (key) => key
    return Plot.plot({
      width: width,
      x: {label: null},
      y: {},
      fy: {label: null, axis: null},
      color: {
        label: "failure", 
        type: "categorical",
        legend: true,
        domain: topFailures,
        range: colorRange
      },
      marks: [
        Plot.rectY(reducedObsByDate, 
          Plot.normalizeY({
            x: "timestamp", 
            y: "observation_count",
            fy: "ip",
            interval: "day",
            fill: "failure",
            tip: true,
          })
        ),
        Plot.text(keys, {fy, text: (d) => (d), frameAnchor: "top-left", dx: 6, dy: 6}),
        Plot.frame(),
      ]
    })
  } else {
    return Plot.plot({
      width: width,
      x: {label: null},
      y: {},
      color: {
        label: "failure",
        type: "categorical",
        legend: true,
        domain: topFailures,
        range: colorRange
      },
      marks: [
        Plot.rectY(reducedObsByDate, 
          {
            x: "timestamp", 
            y: "observation_count",
            interval: "day",
            fill: "failure",
            tip: true,
          }
        ),
      ]
    })
  }
}
```

<div class="card">
<h2>Observation count by failure_type for ${hostnameFilter} in ${countryPicker}</h2>
${resize((width) => plotChart(width))}
</div>