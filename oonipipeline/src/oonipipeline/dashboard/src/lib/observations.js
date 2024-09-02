async function json(url) {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`fetch failed: ${response.status}`);
  return await response.json();
}

export async function getObservationsAggregate(params) {
  const query = Object.keys(params)
    .map((key) => {
      if (Array.isArray(params[key])) {
        return params[key].map((value) => `${key}=${value}`).join("&");
      }
      return `${key}=${params[key]}`;
    })
    .join("&");
  console.log(`running query ${query}`);
  return json(`https://data.ooni.org/api/v2/observations-aggregate?${query}`);
}
