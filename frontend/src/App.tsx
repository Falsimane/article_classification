import { useEffect, useState } from "react";
import { ActorsView } from "./components/ActorsView";
import { ReportsView } from "./components/ReportsView";
import { Shell, type View } from "./components/Shell";
import { api } from "./lib/api";
import { useAsync } from "./lib/useAsync";

export default function App() {
  const [view, setView] = useState<View>(() => (location.pathname.startsWith("/actors") ? "actors" : "reports"));
  const changeView = (v: View) => {
    history.pushState(null, "", v === "actors" ? "/actors" : "/");
    setView(v);
  };
  useEffect(() => {
    const onPop = () => setView(location.pathname.startsWith("/actors") ? "actors" : "reports");
    addEventListener("popstate", onPop);
    return () => removeEventListener("popstate", onPop);
  }, []);
  const stats = useAsync(api.stats, []);
  const articles = useAsync(api.articles, []);
  return (
    <Shell view={view} onView={changeView} stats={stats.data}>
      {articles.error ? (
        <div className="flex h-full items-center justify-center text-sm text-danger">{articles.error}</div>
      ) : articles.data == null ? (
        <div className="flex h-full items-center justify-center text-sm text-faint">Chargement…</div>
      ) : view === "reports" ? (
        <ReportsView articles={articles.data} />
      ) : (
        <ActorsView />
      )}
    </Shell>
  );
}
