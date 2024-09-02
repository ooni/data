// taken from: https://observablehq.com/@mootari/inputs-submit
import * as htl from "npm:htl";

export default function guard(fn, options = {}) {
  const {
    submitLabel = "Submit",
    resetLabel = "Reset",
    required = false,
    resubmit = true,
    width = "fit-content",
    justify = "start",
  } = options;

  const onSubmit = () => {
    value = input.value;
    submit.disabled = !resubmit;
    reset.disabled = true;
    wrapper.dispatchEvent(new Event("input", { bubbles: true }));
  };
  const onReset = () => {
    input.value = value;
    submit.disabled = !resubmit;
    reset.disabled = true;
  };

  const submit = htl.html`<button ${{
    disabled: !resubmit && !required,
    onclick: onSubmit,
  }}>${submitLabel}`;
  const reset = htl.html`<button ${{
    disabled: true,
    onclick: onReset,
  }}>${resetLabel}`;
  const footer = htl.html`<div><hr style="padding:0;margin:10px 0"><div style="display:flex;gap:1ch;justify-content:${justify}">${submit} ${reset}`;
  const template = (inputs) =>
    htl.html`<div>${
      Array.isArray(inputs) ? inputs : Object.values(inputs)
    }${footer}`;

  const input = fn({ submit, reset, footer, template, onSubmit, onReset });
  input.addEventListener("input", (e) => {
    e.stopPropagation();
    submit.disabled = false;
    reset.disabled = false;
  });
  let value = required ? undefined : input.value;
  const wrapper = htl.html`<div style="width:${width}">${input}`;
  wrapper.addEventListener("submit", onSubmit);
  return Object.defineProperty(wrapper, "value", {
    get: () => value,
    set: (v) => {
      input.value = v;
    },
  });
}
