import { useCallback, useMemo } from "react";
import { useSearchParams } from "react-router-dom";

/**
 * Filter state kept in the URL query string, so a filtered view can be bookmarked, shared,
 * linked to from another page, and survives a refresh. Values equal to their default are
 * left out of the URL. Changing any filter other than `keepPage` keys sends `page` back to 0.
 */
export function useFilters<T extends Record<string, string>>(defaults: T, keepPage: readonly string[] = ["page"]) {
  const [params, setParams] = useSearchParams();

  const values = useMemo(() => {
    const result: Record<string, string> = { ...defaults };
    for (const key of Object.keys(defaults)) {
      const value = params.get(key);
      if (value !== null) result[key] = value;
    }
    return result as T;
  }, [params, defaults]);

  const update = useCallback(
    (patch: Partial<T>) => {
      setParams(
        (previous) => {
          const next = new URLSearchParams(previous);
          for (const [key, value] of Object.entries(patch)) {
            if (value === undefined || value === "" || value === defaults[key]) next.delete(key);
            else next.set(key, value as string);
          }
          if (Object.keys(patch).some((key) => !keepPage.includes(key))) next.delete("page");
          return next;
        },
        { replace: true },
      );
    },
    [setParams, defaults, keepPage],
  );

  return [values, update] as const;
}
