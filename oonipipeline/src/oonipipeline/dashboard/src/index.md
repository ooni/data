```js
import * as Plot from "npm:@observablehq/plot"
import colors from "./lib/colors.js"
import guard from "./components/guard.js"
import { makeColorPalette } from "./lib/colorUtils.js"
import { getObservationsAggregate } from "./lib/observations.js"
import { getObservationData, PlotObservationFailures } from "./components/observationFailures.js"
```

## OONI Pipeline dashboard

Fill out the form below to plot observations by failure type

```js
const until = new Date()
var since = new Date()
since.setDate(since.getDate() - 30)

const form = view(
  guard(({template}) => 
    Inputs.form({
      "country": Inputs.text({
        label: "Country Code",
        placeholder: "Enter two letter country code",
        //datalist: capitals.map((d) => d.State)
      }),
      "hostname": Inputs.text({
        label: "Hostname",
        placeholder: "Enter the hostname",
        //datalist: capitals.map((d) => d.State)
        }),
      "since": Inputs.date({label: "Start Date", value: since}),
      "until": Inputs.date({label: "End Date", value: until}),
    },
    { template }
    )
  )
);
```

```js
const hostnameFilter = form.hostname
const countryFilter = form.country
const breakDownByIP = view(Inputs.toggle({label: "By IP", value: false}));
```

```js
let data
if (hostnameFilter && countryFilter) {
  data = await getObservationData({
    countryFilter,
    hostnameFilter,
    breakDownByIP,
  })
}
```
<div class="card">
<h2>Observation count by failure_type for ${hostnameFilter} in ${countryFilter}</h2>
${resize((width) => PlotObservationFailures({...data, breakDownByIP, width}))}
</div>