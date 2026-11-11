import { useCallback, useEffect, useState } from "react";

export function useApi<T>(loader: () => Promise<T>, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const reload = useCallback(async () => {
    setLoading(true); setError("");
    try { setData(await loader()); } catch (reason) {
      const message = reason instanceof Error ? reason.message : "Unable to load data.";
      console.error("API request failed:", message);
      setError(message);
    }
    finally { setLoading(false); }
  }, deps);
  useEffect(() => { void reload(); }, [reload]);
  return { data, loading, error, reload };
}
