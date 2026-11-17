import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, MemoryRouter } from "react-router-dom";
import { App } from "./App";
import "./styles.css";

async function start() {
  const demo = Boolean(import.meta.env.VITE_DEMO);
  if (demo) (await import("./demo/mock")).installMock();
  const Router = demo ? MemoryRouter : BrowserRouter;
  createRoot(document.getElementById("root")!).render(
    <StrictMode>
      <Router>
        <App />
      </Router>
    </StrictMode>,
  );
}
void start();
