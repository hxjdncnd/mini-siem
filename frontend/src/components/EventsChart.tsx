import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { TimeBucket } from "../api/types";
import { formatBucketLabel, formatDateTime, formatNumber } from "../lib/format";

/** Event counts over time as an area chart. Used by the overview and by the IP investigation page. */
export function EventsChart({ buckets, bucketSeconds }: { buckets: TimeBucket[]; bucketSeconds: number }) {
  const points = buckets.map((b) => ({ start: b.start, label: formatBucketLabel(b.start, bucketSeconds), count: b.count }));
  return (
    <div className="chart">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={points} margin={{ top: 6, right: 8, bottom: 0, left: -12 }}>
          <defs>
            <linearGradient id="events-fill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#4cc9a7" stopOpacity={0.45} />
              <stop offset="100%" stopColor="#4cc9a7" stopOpacity={0.02} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke="#1d2a45" vertical={false} />
          <XAxis dataKey="label" tick={{ fill: "#8794b0", fontSize: 11.5 }} tickLine={false} axisLine={{ stroke: "#22304d" }} minTickGap={32} />
          <YAxis tick={{ fill: "#8794b0", fontSize: 11.5 }} tickLine={false} axisLine={false} allowDecimals={false} />
          <Tooltip
            contentStyle={{ background: "#0b1120", border: "1px solid #22304d", borderRadius: 8, fontSize: 12.5 }}
            labelStyle={{ color: "#8794b0" }}
            itemStyle={{ color: "#e5eaf5" }}
            labelFormatter={(_, payload) => {
              const start = payload?.[0]?.payload?.start;
              return start ? formatDateTime(start) : "";
            }}
            formatter={(value) => [formatNumber(Number(value)), "Events"]}
          />
          <Area type="monotone" dataKey="count" stroke="#4cc9a7" strokeWidth={2} fill="url(#events-fill)" isAnimationActive={false} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
