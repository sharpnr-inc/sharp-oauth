import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App.jsx";
import { relayPopupCallback } from "./oauth.js";
import "./styles.css";

// In popup sign-in, this page is the popup coming back on /callback: it
// passes the result to the main window and closes without rendering.
if (!relayPopupCallback()) {
  createRoot(document.getElementById("root")).render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
}
