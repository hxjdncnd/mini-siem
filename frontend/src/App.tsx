import { Link, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { Alerts } from "./pages/Alerts";
import { Events } from "./pages/Events";
import { Overview } from "./pages/Overview";
import { Rules } from "./pages/Rules";

export function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Overview />} />
        <Route path="alerts" element={<Alerts />} />
        <Route path="events" element={<Events />} />
        <Route path="rules" element={<Rules />} />
        <Route
          path="*"
          element={
            <div className="state">
              <strong>Page not found</strong>
              <Link to="/">Back to the overview</Link>
            </div>
          }
        />
      </Route>
    </Routes>
  );
}
