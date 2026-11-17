import { Link } from "react-router-dom";

/** An address that opens its investigation page. Safe inside clickable table rows. */
export function IpLink({ ip }: { ip: string }) {
  return (
    <Link className="mono" to={`/ips/${encodeURIComponent(ip)}`} onClick={(event) => event.stopPropagation()}>
      {ip}
    </Link>
  );
}
