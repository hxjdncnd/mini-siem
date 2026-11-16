import { useEffect, useState } from "react";

/** A text box that applies its value on Enter or when it loses focus, not on every keystroke. */
export function TextFilter({
  label,
  value,
  onCommit,
  placeholder,
  width = 150,
}: {
  label: string;
  value: string;
  onCommit: (value: string) => void;
  placeholder?: string;
  width?: number;
}) {
  const [draft, setDraft] = useState(value);
  useEffect(() => setDraft(value), [value]);
  const commit = () => {
    if (draft.trim() !== value) onCommit(draft.trim());
  };
  const id = `filter-${label.replace(/\s+/g, "-").toLowerCase()}`;
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <input
        id={id}
        style={{ width }}
        value={draft}
        placeholder={placeholder}
        onChange={(event) => setDraft(event.target.value)}
        onBlur={commit}
        onKeyDown={(event) => {
          if (event.key === "Enter") commit();
        }}
      />
    </div>
  );
}
