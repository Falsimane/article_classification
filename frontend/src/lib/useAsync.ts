import { useEffect, useState } from "react";

export interface Async<T> { data: T | null; error: string | null; loading: boolean }

/** Charge `load()` à chaque changement de `deps` ; une réponse tardive d'une requête périmée est ignorée. */
export function useAsync<T>(load: () => Promise<T>, deps: unknown[]): Async<T> {
  const [state, setState] = useState<Async<T>>({ data: null, error: null, loading: true });
  useEffect(() => {
    let current = true;
    setState((s) => ({ ...s, loading: true, error: null }));
    load().then(
      (data) => current && setState({ data, error: null, loading: false }),
      (e: Error) => current && setState({ data: null, error: e.message, loading: false }),
    );
    return () => { current = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  return state;
}
