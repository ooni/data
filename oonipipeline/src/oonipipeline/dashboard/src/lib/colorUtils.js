export function makeColorPalette(colorList, colors) {
  let palette = [];
  let names = [];
  colorList.forEach((c) => {
    const regexp = /([a-zA-Z]+)\[(\d+)\]/;
    const m = c.match(regexp);
    const colorName = m[1];
    const colorIdx = `${m[2]}`;
    palette.push(colors[colorName][colorIdx]);
    names.push(c);
  });
  return {
    palette,
    names,
  };
}

export function plotColorRange(colorName, colors) {
  const colorScale = [
    "50",
    "100",
    "200",
    "300",
    "400",
    "500",
    "600",
    "700",
    "800",
    "900",
  ];
  const colorRange = colorScale.map((d) => colors[colorName][d]);
  return Plot.legend({
    color: {
      type: "categorical",
      domain: colorScale.map((d) => `${colorName}[${d}]`),
      range: colorRange,
    },
  });
}

export function plotColorPalette({ palette, names }) {
  return Plot.legend({
    color: {
      type: "categorical",
      domain: names,
      range: palette,
    },
  });
}
