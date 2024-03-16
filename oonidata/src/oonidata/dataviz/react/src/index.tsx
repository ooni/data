import * as React from "react";
import * as ReactDOM from "react-dom";
import { HashRouter } from "react-router-dom";
import "@fontsource/fira-sans";

import App from "./App";

document.addEventListener("DOMContentLoaded", (event) => {
  ReactDOM.render(
    <HashRouter>
      <App />
    </HashRouter>,
    document.getElementById("root")
  );
});
