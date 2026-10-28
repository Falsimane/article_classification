import json
import sqlite3
import subprocess
import shutil
from pathlib import Path

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll, Container
from textual.widgets import Header, Footer, Markdown, Button, Label
from textual.reactive import reactive
from rich.console import Console
from rich.prompt import Prompt
from rich.panel import Panel

BASE_DIR = Path(__file__).resolve().parents[2]
DB_PATH = BASE_DIR / "db_outputs" / "cti_knowledge.db"

def get_articles_to_review(mode: str = "douteux", limit: int = 50) -> list:
    with sqlite3.connect(DB_PATH, timeout=10.0) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        if mode == "douteux":
            query = """
                SELECT k.id, k.title, k.url, k.publication_date, k.content AS raw_content,
                       c.primary_category, c.score_tactical, c.score_operational, 
                       c.score_strategic, c.clean_markdown,
                       c.sections_meta, c.is_processable, c.reject_reason,
                       c.rationale, c.human_category, c.is_validated
                FROM knowledge k
                JOIN article_classifications c ON k.id = c.knowledge_id
                WHERE (c.is_validated = 0 OR c.is_validated IS NULL)
                  AND (
                       (c.score_tactical = 0 AND c.score_operational = 0 AND c.score_strategic = 0 AND c.primary_category != 'out_of_scope')
                    OR (ABS(c.score_tactical - c.score_operational) < 0.20 AND c.score_tactical > 0.35)
                    OR (c.primary_category = 'error')
                  )
                ORDER BY c.id ASC
                LIMIT ?;
            """
            cursor.execute(query, (limit,))
        else:
            query = """
                SELECT k.id, k.title, k.url, k.publication_date, k.content AS raw_content,
                       c.primary_category, c.score_tactical, c.score_operational, 
                       c.score_strategic, c.clean_markdown,
                       c.sections_meta, c.is_processable, c.reject_reason,
                       c.rationale, c.human_category, c.is_validated
                FROM knowledge k
                JOIN article_classifications c ON k.id = c.knowledge_id
                WHERE c.primary_category = ? 
                  AND (c.is_validated = 0 OR c.is_validated IS NULL)
                ORDER BY RANDOM()
                LIMIT ?;
            """
            cursor.execute(query, (mode, limit))

        articles = [dict(row) for row in cursor.fetchall()]
        return articles

def save_human_verdict(knowledge_id: int, final_category: str) -> None:
    with sqlite3.connect(DB_PATH, timeout=10.0) as conn:
        conn.execute("""
            UPDATE article_classifications
            SET human_category = ?, is_validated = 1
            WHERE knowledge_id = ?;
        """, (final_category, knowledge_id))
        conn.commit()

class CTIAuditApp(App):
    CSS = """
    Screen { layout: horizontal; background: $surface; }
    #left-pane { width: 65%; height: 100%; border-right: heavy $accent; padding: 0 1; }
    #article-meta-header { height: auto; background: $surface-darken-1; border-bottom: solid $primary; padding: 1; margin-bottom: 1; }
    #doc-mode-indicator { color: $text-muted; text-style: italic; margin-bottom: 1; }
    #markdown-scroll { height: 1fr; border: solid $surface-lighten-1; padding: 0 1; }
    #right-pane { width: 35%; height: 100%; padding: 0 1; overflow-y: auto; }
    .card { background: $surface-darken-1; border: solid $secondary; padding: 1; margin-bottom: 1; height: auto; }
    .card-title { text-style: bold; color: $accent; margin-bottom: 1; border-bottom: solid $secondary-darken-2; }
    .btn-grid { layout: grid; grid-size: 2; grid-gutter: 1; margin-top: 1; }
    Button { width: 100%; }
    #btn-validate { background: $success; color: white; }
    #btn-op { background: #b58900; color: white; }
    #btn-tac { background: #dc322f; color: white; }
    #btn-strat { background: #268bd2; color: white; }
    #btn-oos { background: #6c71c4; color: white; }
    #btn-skip { background: $surface-lighten-2; }
    """

    BINDINGS = [
        Binding("v", "validate", "Valider", priority=True),
        Binding("o", "force_op", "Opérationnel", priority=True),
        Binding("t", "force_tac", "Tactique", priority=True),
        Binding("s", "force_strat", "Stratégique", priority=True),
        Binding("x", "force_oos", "Hors-périmètre", priority=True),
        Binding("p", "skip", "Passer", priority=True),
        Binding("b", "toggle_mode", "Basculer Brut/Nettoyé", priority=True),
        Binding("e", "open_vscode", "Éditeur externe", priority=True),
        Binding("q", "quit", "Quitter", priority=True),
    ]

    current_index = reactive(0)
    use_raw_content = reactive(False)

    def __init__(self, articles: list, mode_label: str):
        super().__init__()
        self.articles = articles
        self.mode_label = mode_label
        self.stats = {"validated": 0, "corrected": 0, "skipped": 0}

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal():
            with Vertical(id="left-pane"):
                with Container(id="article-meta-header"):
                    yield Label(id="lbl-article-title", classes="card-title")
                    yield Label(id="lbl-article-sub")
                    yield Label(id="doc-mode-indicator")
                with VerticalScroll(id="markdown-scroll"):
                    yield Markdown(id="article-markdown-body")

            with Vertical(id="right-pane"):
                with Container(classes="card"):
                    yield Label("1. CLASSIFICATION & SCORES", classes="card-title")
                    yield Label(id="lbl-category-badge")
                    yield Label(id="lbl-scores")
                    yield Label(id="lbl-rationale")

                with Container(classes="card"):
                    yield Label("2. STRUCTURE DU DOCUMENT (SECTIONS)", classes="card-title")
                    yield Label(id="lbl-doc-status")
                    yield Label(id="lbl-doc-sections")

                with Container(classes="card"):
                    yield Label("3. ARBITRAGE HUMAIN", classes="card-title")
                    yield Label(id="lbl-progress-status")
                    with Container(classes="btn-grid"):
                        yield Button("Valider [V]", id="btn-validate")
                        yield Button("Passer [P]", id="btn-skip")
                        yield Button("Opérationnel [O]", id="btn-op")
                        yield Button("Tactique [T]", id="btn-tac")
                        yield Button("Stratégique [S]", id="btn-strat")
                        yield Button("Hors-Périmètre [X]", id="btn-oos")
        yield Footer()

    def on_mount(self) -> None:
        self.update_current_article_view()

    def update_current_article_view(self) -> None:
        if not self.articles or self.current_index >= len(self.articles):
            self.exit()
            return

        art = self.articles[self.current_index]
        total = len(self.articles)
        idx_disp = self.current_index + 1

        self.query_one("#lbl-article-title", Label).update(f"[{idx_disp}/{total}] ID {art['id']} : {art['title']}")
        self.query_one("#lbl-article-sub", Label).update(f"URL : {art['url']}  •  Date : {art['publication_date'] or 'N/A'}")

        mode_str = "BRUT ORIGINAL" if self.use_raw_content else "NETTOYÉ (CLEAN MARKDOWN)"
        self.query_one("#doc-mode-indicator", Label).update(f"Mode de lecture : [bold cyan]{mode_str}[/] (Touche [bold]B[/] pour basculer)")

        display_md = art["raw_content"] if self.use_raw_content else (art.get("clean_markdown") or art["raw_content"])
        self.query_one("#article-markdown-body", Markdown).update(display_md)

        # Carte 1 : Classification & Scores
        cat = art["primary_category"].upper()
        self.query_one("#lbl-category-badge", Label).update(f"Verdict : [bold underline]{cat}[/]")
        self.query_one("#lbl-scores", Label).update(
            f"Scores : [red]T: {art['score_tactical']:.2f}[/] │ [yellow]O: {art['score_operational']:.2f}[/] │ [cyan]S: {art['score_strategic']:.2f}[/]"
        )
        self.query_one("#lbl-rationale", Label).update(f"Rationale : [dim]{art['rationale']}[/]")

        # Carte 2 : Structure & Sections
        is_proc = art.get("is_processable", 1)
        rej = art.get("reject_reason")
        if is_proc == 0 and rej:
            self.query_one("#lbl-doc-status", Label).update(f"Statut : [bold red]REJET AMONT (0ms)[/]\nMotif : [yellow]{rej}[/]")
            self.query_one("#lbl-doc-sections", Label).update("")
        else:
            try:
                sections = json.loads(art.get("sections_meta") or "[]")
            except Exception:
                sections = []

            self.query_one("#lbl-doc-status", Label).update(f"Statut : [bold green]Document Traitable[/] ({len(sections)} sections)")
            sec_summaries = []
            for s in sections[:6]:
                phase = s.get("kill_chain_phase")
                phase_tag = f" [cyan][{phase}][/cyan]" if phase else ""
                sec_summaries.append(f"• {'#' * s.get('level', 1)} {s.get('title', '')}{phase_tag} ({s.get('char_count', 0)} car.)")
            if len(sections) > 6:
                sec_summaries.append(f"... + {len(sections) - 6} autres sections")
            self.query_one("#lbl-doc-sections", Label).update("\n".join(sec_summaries) if sec_summaries else "[dim]Aucune section[/]")

        # Progression
        self.query_one("#lbl-progress-status", Label).update(
            f"Session : {self.stats['validated']} validés │ {self.stats['corrected']} corrigés"
        )
        self.query_one("#markdown-scroll", VerticalScroll).scroll_home(animate=False)

    def action_toggle_mode(self) -> None:
        self.use_raw_content = not self.use_raw_content
        self.update_current_article_view()

    def action_validate(self) -> None:
        art = self.articles[self.current_index]
        save_human_verdict(art["id"], art["primary_category"])
        self.stats["validated"] += 1
        self.advance()

    def action_force_op(self) -> None:
        art = self.articles[self.current_index]
        save_human_verdict(art["id"], "operational")
        self.stats["corrected"] += 1
        self.advance()

    def action_force_tac(self) -> None:
        art = self.articles[self.current_index]
        save_human_verdict(art["id"], "tactical")
        self.stats["corrected"] += 1
        self.advance()

    def action_force_strat(self) -> None:
        art = self.articles[self.current_index]
        save_human_verdict(art["id"], "strategic")
        self.stats["corrected"] += 1
        self.advance()

    def action_force_oos(self) -> None:
        art = self.articles[self.current_index]
        save_human_verdict(art["id"], "out_of_scope")
        self.stats["corrected"] += 1
        self.advance()

    def action_skip(self) -> None:
        self.stats["skipped"] += 1
        self.advance()

    def action_open_vscode(self) -> None:
        art = self.articles[self.current_index]
        tmp_path = Path(f"/tmp/cti_review_{art['id']}.md")
        content = art["raw_content"] if self.use_raw_content else (art.get("clean_markdown") or art["raw_content"])
        tmp_path.write_text(f"# {art['title']}\n\n{content}", encoding="utf-8")
        if shutil.which("code"):
            subprocess.run(["code", str(tmp_path)], check=False)

    def advance(self) -> None:
        self.current_index += 1
        if self.current_index < len(self.articles):
            self.update_current_article_view()
        else:
            self.exit()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id
        if btn_id == "btn-validate":
            self.action_validate()
        elif btn_id == "btn-op":
            self.action_force_op()
        elif btn_id == "btn-tac":
            self.action_force_tac()
        elif btn_id == "btn-strat":
            self.action_force_strat()
        elif btn_id == "btn-oos":
            self.action_force_oos()
        elif btn_id == "btn-skip":
            self.action_skip()

def main():
    console = Console()
    console.print(Panel.fit(
        "[bold cyan]🛡️ Module d'Audit CTI Hybride V3 (Rust Preprocessor + Qwen-32b)[/]\n"
        "[dim]Contrôle qualité et validation des catégories CTI (Operational, Tactical, Strategic, Out of Scope)[/]",
        border_style="cyan"
    ))

    console.print("[bold]Sélectionnez la catégorie à inspecter :[/]")
    console.print("  [bold red]1.[/] Cas [bold red]douteux / litigieux[/] (scores serrés T vs O, scores nuls, erreurs)")
    console.print("  [bold yellow]2.[/] Échantillon [bold yellow]Opérationnel[/]")
    console.print("  [bold red]3.[/] Échantillon [bold red]Tactique[/]")
    console.print("  [bold cyan]4.[/] Échantillon [bold cyan]Stratégique[/]")
    console.print("  [bold magenta]5.[/] Échantillon [bold magenta]Hors-périmètre (out_of_scope)[/]")
    console.print("  [dim]Q. Quitter[/]\n")

    choice = Prompt.ask("Sélection", choices=["1", "2", "3", "4", "5", "q"], default="1")
    if choice.lower() == "q":
        return

    mode_map = {"1": "douteux", "2": "operational", "3": "tactical", "4": "strategic", "5": "out_of_scope"}
    selected_mode = mode_map[choice]

    articles = get_articles_to_review(selected_mode, limit=50)
    if not articles:
        console.print("[bold green]✓ Aucun article en attente d'audit pour ce filtre ![/]")
        return

    app = CTIAuditApp(articles=articles, mode_label=selected_mode)
    app.run()

    console.print("\n")
    console.print(Panel(
        f"[green]Validés :[/] {app.stats['validated']}  │  "
        f"[yellow]Corrigés :[/] {app.stats['corrected']}  │  "
        f"[dim]Passés :[/] {app.stats['skipped']}",
        title="📊 Bilan de session d'audit",
        border_style="green",
        expand=False
    ))

if __name__ == "__main__":
    main()