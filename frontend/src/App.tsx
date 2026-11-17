import { Link, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { Alerts } from "./pages/Alerts";
import { Events } from "./pages/Events";
import { IpDetail } from "./pages/IpDetail";
import { Overview } from "./pages/Overview";
import { Rules } from "./pages/Rules";
import { Upload } from "./pages/Upload";

export function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Overview />} />
        <Route path="alerts" element={<Alerts />} />
        <Route path="events" element={<Events />} />
        <Route path="ips/:ip" element={<IpDetail />} />
        <Route path="upload" element={<Upload />} />
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
