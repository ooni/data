import * as React from "react";

import { createGlobalStyle, ThemeProvider } from "styled-components";

import { Container, theme } from "ooni-components";

import { Routes, Route, Outlet, Link } from "react-router-dom";

import DataViz from './components/Dataviz'
import DNSAnalysis from "./components/DNSAnalysis";

const GlobalStyle = createGlobalStyle`
  * {
    text-rendering: geometricPrecision;
    box-sizing: border-box;
  }
  body, html {
    margin: 0;
    padding: 0;
    font-family: "Fira Sans";
    font-size: 14px;
    height: 100%;
    background-color: #ffffff;
  }
`;

const Layout = () => (
  <ThemeProvider theme={theme}>
    <GlobalStyle />
    <Container>
      <Outlet />

    </Container>
  </ThemeProvider>
)

const Home = () => (
  <div>Hello home</div>
)

const App = () => {
  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={<Home />} />
        <Route path="dnsanalysis" element={<DNSAnalysis />} />
        <Route path="dataviz" element={<DataViz />} />
        <Route path="*" element={<Home />} />
      </Route>
    </Routes>
  );
};

export default App;
