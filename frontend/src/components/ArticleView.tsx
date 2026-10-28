import Markdown, { type Components } from "react-markdown";
import remarkGfm from "remark-gfm";
import type { ArticleText } from "../types";

// react-markdown construit des éléments React : le HTML brut de l'article est affiché comme texte, jamais interprété.
// Les images ne sont pas chargées (requête vers un hôte tiers) : leur lien est affiché à la place.
const COMPONENTS: Components = {
  h1: ({ children }) => <h1 className="mb-3 mt-6 text-xl font-semibold leading-7">{children}</h1>,
  h2: ({ children }) => <h2 className="mb-2 mt-6 border-b border-line pb-1 text-lg font-semibold leading-6">{children}</h2>,
  h3: ({ children }) => <h3 className="mb-2 mt-5 text-base font-semibold">{children}</h3>,
  h4: ({ children }) => <h4 className="mb-1 mt-4 text-sm font-semibold uppercase tracking-wide text-muted">{children}</h4>,
  p: ({ children }) => <p className="my-2 leading-6">{children}</p>,
  a: ({ href, children }) => <a href={href} target="_blank" rel="noreferrer noopener" className="break-words text-accent hover:underline">{children}</a>,
  img: ({ src, alt }) => (
    <a href={typeof src === "string" ? src : undefined} target="_blank" rel="noreferrer noopener" className="font-mono text-xs text-faint hover:text-ink">[image{alt ? ` : ${alt}` : ""}]</a>
  ),
  ul: ({ children }) => <ul className="my-2 list-disc space-y-1 pl-6">{children}</ul>,
  ol: ({ children }) => <ol className="my-2 list-decimal space-y-1 pl-6">{children}</ol>,
  blockquote: ({ children }) => <blockquote className="my-3 border-l-2 border-line-strong pl-3 text-muted">{children}</blockquote>,
  pre: ({ children }) => <pre className="my-3 overflow-x-auto border border-line bg-panel p-3 font-mono text-xs leading-5">{children}</pre>,
  code: ({ children }) => <code className="break-words font-mono text-xs text-ink">{children}</code>,
  table: ({ children }) => <div className="my-3 overflow-x-auto"><table className="w-full border-collapse text-sm">{children}</table></div>,
  th: ({ children }) => <th className="border border-line bg-panel px-2 py-1 text-left font-medium">{children}</th>,
  td: ({ children }) => <td className="break-all border border-line px-2 py-1 align-top">{children}</td>,
  hr: () => <hr className="my-4 border-line" />,
};

export function ArticleView({ article }: { article: ArticleText }) {
  return (
    <article className="mx-auto max-w-[860px] px-8 py-6 text-base">
      <header className="mb-4 border-b border-line pb-3">
        <h1 className="text-xl font-semibold leading-7">{article.title}</h1>
        <div className="mt-1 flex flex-wrap gap-3 font-mono text-[10px] uppercase tracking-wide text-faint">
          <span>{article.site_name ?? "—"}</span>
          {article.published && <span>{article.published}</span>}
          {article.category && <span>{article.category}</span>}
          {article.url && <a href={article.url} target="_blank" rel="noreferrer noopener" className="normal-case tracking-normal text-accent hover:underline">source</a>}
        </div>
      </header>
      {article.markdown ? <Markdown remarkPlugins={[remarkGfm]} components={COMPONENTS}>{article.markdown}</Markdown> : <p className="text-sm text-faint">Texte nettoyé indisponible.</p>}
      <p className="mt-6 border-t border-line pt-3 text-xs text-faint">
        Texte nettoyé par le preprocessing, exactement celui que l'extraction a lu (les phrases de preuve du graphe en sont tirées).
      </p>
    </article>
  );
}
