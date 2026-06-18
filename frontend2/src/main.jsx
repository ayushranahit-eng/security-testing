import React from "react";
import { createRoot } from "react-dom/client";
import LandingGate from "./LandingGate.jsx";
import "./styles.css";

createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <LandingGate />
  </React.StrictMode>,
);
