import { Suspense, lazy, useEffect, useState } from "react";
import { ActorsView } from "./components/ActorsView";
import { ReportsView } from "./components/ReportsView";
import { Shell, type View } from "./components/Shell";
import { api } from "./lib/api";
import { useAsync } from "./lib/useAsync";

// sigma et graphology ne sont chargés qu'à l'ouverture du graphe global
const GlobalView = lazy(() => import("./components/GlobalView").then((m) => ({ default: m.GlobalView })));

export default function App() {
  const viewOfPath = (): View => (location.pathname.startsWith("/actors") ? "actors" : location.pathname.startsWith("/graph") ? "graph" : "reports");
  const [view, setView] = useState<View>(viewOfPath);
  const changeView = (v: View) => {
    history.pushState(null, "", v === "reports" ? "/" : `/${v}`);
    setView(v);
  };
  useEffect(() => {
    const onPop = () => setView(viewOfPath());
    addEventListener("popstate", onPop);
    return () => removeEventListener("popstate", onPop);
  }, []);
  const [revision, setRevision] = useState(0); // incrémentée après une suppression : articles et totaux sont relus
  const stats = useAsync(api.stats, [revision]);
  const articles = useAsync(api.articles, [revision]);
  return (
    <Shell view={view} onView={changeView} stats={stats.data}>
      {articles.error ? (
        <div className="flex h-full items-center justify-center text-sm text-danger">{articles.error}</div>
      ) : articles.data == null ? (
        <div className="flex h-full items-center justify-center text-sm text-faint">Chargement…</div>
      ) : view === "graph" ? (
        <Suspense fallback={<div className="flex h-full items-center justify-center text-sm text-faint">Chargement…</div>}><GlobalView /></Suspense>
      ) : view === "reports" ? (
        <ReportsView articles={articles.data} onDeleted={() => setRevision((r) => r + 1)} />
      ) : (
        <ActorsView />
      )}
    </Shell>
  );
}
