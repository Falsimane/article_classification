//! Moteur déterministe de preprocessing CTI.
//!
//! Entrée : la page HTML brute de l'article (`process_html`). Sortie : un Markdown canonique (titres `#`, paragraphes,
//! listes `- `, code clôturé, tables `|`) que l'aval découpe avec `split_blocks` et `chunk_markdown`.
//!
//! Principes :
//! - purement structurel : aucune liste d'acteurs, d'outils ou d'éditeurs en dur ;
//! - le bruit est reconnu dans le DOM (éléments cachés ou de navigation, densité de liens, racine du contenu, voir
//!   `html.rs`) et par apprentissage du gabarit de chaque site sur le corpus (`html_template_keys`) ;
//! - les blocs de code et les tables sont atomiques : jamais déplacés, jamais tronqués ;
//! - aucune extraction d'entités ni d'IOCs : les IOCs restent dans leur contexte narratif.

mod html;

use pyo3::prelude::*;
use regex::{Captures, Regex};
use std::collections::HashSet;

const MIN_VIABLE_CHARS: usize = 200;
/// Un document court contenant une de ces signatures est une page d'erreur de scraping.
const ERROR_PAGE_MAX_CHARS: usize = 1500;

#[pyclass(get_all)]
#[derive(Clone, Debug)]
pub struct ArticleSection {
    pub section_index: usize,
    pub title: String,
    pub level: u8,
    pub content: String,
    pub char_count: usize,
    pub is_appendix_ioc: bool,
    /// Chemin hiérarchique des titres (« H1 > H2 > H3 ») : en-tête contextuel pour tout découpage aval.
    pub heading_path: String,
    /// Unités atomiques de la section (paragraphes, blocs de code, tables) : un découpage aval
    /// doit se faire entre elles, jamais à l'intérieur.
    pub blocks: Vec<String>,
}

#[pyclass(get_all)]
#[derive(Clone, Debug)]
pub struct PreprocessingResult {
    pub is_processable: bool,
    pub reject_reason: Option<String>,
    pub clean_markdown: String,
    pub sections: Vec<ArticleSection>,
}

/// Bloc atomique du Markdown nettoyé, avec le chemin des titres qui le contient.
#[pyclass(get_all)]
#[derive(Clone, Debug)]
pub struct MdBlock {
    /// "heading" | "code" | "table" | "text"
    pub kind: String,
    pub level: u8,
    pub heading_path: String,
    pub text: String,
}

/// Segment de texte prêt pour l'extraction aval : bornes toujours entre blocs atomiques.
#[pyclass(get_all)]
#[derive(Clone, Debug)]
pub struct Chunk {
    pub chunk_index: usize,
    /// Chemin hiérarchique actif au début du segment (« H1 > H2 ») : contexte à injecter dans le prompt.
    pub heading_path: String,
    pub titles: Vec<String>,
    pub text: String,
    pub char_count: usize,
    /// Vrai si un unique bloc atomique (code, table, paragraphe) dépasse seul le budget : il n'est jamais coupé.
    pub oversized: bool,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Kind {
    Heading(u8),
    Code,
    Table,
    Text,
}

#[derive(Clone, Debug)]
struct Block {
    kind: Kind,
    text: String,
}

#[pyclass]
pub struct CtiEngine {
    re_error_page: Regex,
    re_hxxp: Regex,
    re_dot: Regex,
    re_at: Regex,
    re_code_dot: Regex,
    re_half_dot: Regex,
    re_hex_hash: Regex,
    re_ioc_hint: Regex,
    re_ioc_density: Regex,
    re_date: Regex,
    re_shortcode: Regex,
}

impl Default for CtiEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[pymethods]
impl CtiEngine {
    #[new]
    pub fn new() -> Self {
        let rx = |p: &str| Regex::new(p).unwrap();
        Self {
            re_error_page: rx(
                r"(?i)access denied|403 forbidden|404 not found|page not found|just a moment|checking your browser|enable javascript|captcha|attention required|service unavailable|too many requests|are you a robot|verify you are human",
            ),
            re_hxxp: rx(r"(?i)hxxp(s?)"),
            re_dot: rx(r"(?i)[\[\(\{]\s*(?:\.|dot)\s*[\]\)\}]"),
            re_at: rx(r"(?i)[\[\(\{]\s*(?:@|at)\s*[\]\)\}]"),
            re_code_dot: rx(r"(\w)\[\.\](\w)"),
            // Neutralisations « à moitié fermées » : `domaine.]com`, `domaine[.com`
            re_half_dot: rx(r"(\w)(?:\.\]|\[\.)(\w)"),
            re_hex_hash: rx(r"[a-fA-F0-9]{32,}"),
            re_ioc_hint: rx(
                r"(?i)\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|\b[a-f0-9]{32,64}\b|https?://|\bCVE-\d{4}-\d{4,7}\b",
            ),
            re_date: rx(
                r"(?i)\b(?:19|20)\d{2}[-/.]\d{1,2}[-/.]\d{1,2}\b|\b\d{1,2}[-/.]\d{1,2}[-/.](?:19|20)\d{2}\b|\b(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.? \d{1,2}(?:st|nd|rd|th)?,? (?:19|20)\d{2}\b|\b\d{1,2}(?:st|nd|rd|th)? (?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]* (?:19|20)\d{2}\b",
            ),
            // Shortcodes d'un constructeur de pages laissés tels quels dans le HTML : `[nom clé="…"]…[/nom]`
            re_shortcode: rx(r"\[(/?)([A-Za-z][\w:-]*)((?:\s[^\]]*)?)\]"),
            re_ioc_density: rx(
                r"(?i)\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|\b[a-f0-9]{32,64}\b|https?://\S+|\bCVE-\d{4}-\d{4,7}\b",
            ),
        }
    }

    /// Dé-neutralisation universelle du texte courant (hors blocs de code).
    pub fn refang(&self, text: &str) -> String {
        let mut t = self.re_hxxp.replace_all(text, "http$1").to_string();
        t = t
            .replace("[://]", "://")
            .replace("[:]//", "://")
            .replace(":[//]", "://")
            .replace("[:]", ":");
        t = self.re_dot.replace_all(&t, ".").to_string();
        t = self.re_half_dot.replace_all(&t, "$1.$2").to_string();
        t = self.re_at.replace_all(&t, "@").to_string();
        t
    }

    /// Découpe un `clean_markdown` en segments d'au plus `max_chars` caractères, en ne coupant
    /// jamais un bloc de code, une table ou un paragraphe, et en gardant chaque titre avec son
    /// premier bloc. Sans recouvrement : aucune duplication de texte (donc aucun IOC dupliqué).
    pub fn chunk_markdown(&self, clean_markdown: &str, max_chars: usize) -> Vec<Chunk> {
        let blocks = parse_blocks(&normalize_input(clean_markdown));
        let mut chunks: Vec<Chunk> = Vec::new();
        let mut stack: Vec<(u8, String)> = Vec::new();
        let mut pending: Vec<(String, usize)> = Vec::new(); // (texte rendu, nb de caractères)
        let mut pending_titles: Vec<String> = Vec::new();

        let mut cur: Vec<String> = Vec::new();
        let mut cur_len = 0usize;
        let mut cur_titles: Vec<String> = Vec::new();
        let mut cur_path = String::new();
        let mut path_now = String::new();

        let flush = |chunks: &mut Vec<Chunk>, cur: &mut Vec<String>, cur_len: &mut usize, titles: &mut Vec<String>, path: &str, oversized: bool| {
            if cur.is_empty() {
                return;
            }
            let text = cur.join("\n\n");
            chunks.push(Chunk {
                chunk_index: chunks.len(),
                heading_path: path.to_string(),
                titles: std::mem::take(titles),
                char_count: text.chars().count(),
                text,
                oversized,
            });
            cur.clear();
            *cur_len = 0;
        };

        for b in &blocks {
            if let Kind::Heading(l) = b.kind {
                while stack.last().map_or(false, |(lv, _)| *lv >= l) {
                    stack.pop();
                }
                stack.push((l, b.text.clone()));
                path_now = stack.iter().map(|(_, t)| t.as_str()).collect::<Vec<_>>().join(" > ");
                let rendered = format!("{} {}", "#".repeat(l as usize), b.text);
                let n = rendered.chars().count();
                pending.push((rendered, n));
                pending_titles.push(b.text.clone());
                continue;
            }
            let body_len = b.text.chars().count();
            let unit_len: usize = pending.iter().map(|(_, n)| n + 2).sum::<usize>() + body_len;
            if !cur.is_empty() && cur_len + unit_len + 2 > max_chars {
                flush(&mut chunks, &mut cur, &mut cur_len, &mut cur_titles, &cur_path, false);
            }
            if cur.is_empty() {
                cur_path = path_now.clone();
            }
            for (r, n) in pending.drain(..) {
                cur.push(r);
                cur_len += n + 2;
            }
            cur_titles.append(&mut pending_titles);
            cur.push(b.text.clone());
            cur_len += body_len + 2;
            if cur_len > max_chars {
                // Bloc atomique plus grand que le budget : segment à part, jamais coupé.
                flush(&mut chunks, &mut cur, &mut cur_len, &mut cur_titles, &cur_path, true);
            }
        }
        flush(&mut chunks, &mut cur, &mut cur_len, &mut cur_titles, &cur_path, false);
        chunks
    }

    /// Blocs atomiques d'un `clean_markdown` dans l'ordre du document, chacun avec son chemin de titres.
    /// Permet à l'aval de numéroter des unités de texte (phrases) sans réimplémenter l'analyse Markdown.
    pub fn split_blocks(&self, clean_markdown: &str) -> Vec<MdBlock> {
        let mut stack: Vec<(u8, String)> = Vec::new();
        let mut out = Vec::new();
        for b in parse_blocks(&normalize_input(clean_markdown)) {
            let (kind, level) = match b.kind {
                Kind::Heading(l) => {
                    while stack.last().map_or(false, |(lv, _)| *lv >= l) {
                        stack.pop();
                    }
                    stack.push((l, b.text.clone()));
                    ("heading", l)
                }
                Kind::Code => ("code", 0),
                Kind::Table => ("table", 0),
                Kind::Text => ("text", 0),
            };
            let path = stack.iter().map(|(_, t)| t.as_str()).collect::<Vec<_>>().join(" > ");
            out.push(MdBlock { kind: kind.to_string(), level, heading_path: path, text: b.text });
        }
        out
    }

    /// Fast-reject : pages vides, coquilles et pages d'erreur de scraping (sur le texte visible de la page).
    pub fn check_viability(&self, text: &str) -> (bool, Option<String>) {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return (false, Some("Article vide (0 caractère)".into()));
        }
        let n = trimmed.chars().count();
        if n < MIN_VIABLE_CHARS {
            return (
                false,
                Some(format!("Contenu trop court ({} < {} caractères)", n, MIN_VIABLE_CHARS)),
            );
        }
        if n < ERROR_PAGE_MAX_CHARS {
            if let Some(m) = self.re_error_page.find(trimmed) {
                return (
                    false,
                    Some(format!("Signature de page d'erreur de scraping : « {} »", m.as_str())),
                );
            }
        }
        (true, None)
    }

    /// Clés de gabarit d'une page : un bloc feuille (chemin de balises + texte normalisé) par clé. Une clé présente dans
    /// assez de pages d'un même site est du gabarit (menus, bannières, pieds de page, appels à l'action) : c'est le corpus
    /// qui le désigne, aucune liste en dur. Jamais de titre, de code, de table ni de texte portant un IOC.
    pub fn html_template_keys(&self, html: &str) -> Vec<String> {
        html::Page::parse(self, html, None).template_keys()
    }

    /// Texte visible de toute la page (hors scripts, formulaires et éléments cachés), un bloc par ligne : la référence à
    /// laquelle on compare le texte nettoyé (fidélité des IOC, taux de conservation).
    pub fn html_text(&self, html: &str) -> String {
        html::Page::parse(self, html, None).text()
    }

    /// Page HTML brute -> Markdown canonique nettoyé et ses sections. `boilerplate` : clés du gabarit appris pour le site
    /// (`html_template_keys`) ; `source_url` distingue les liens internes (navigation) des références externes.
    #[pyo3(signature = (html, boilerplate=None, source_url=None))]
    pub fn process_html(
        &self,
        html: &str,
        boilerplate: Option<Vec<String>>,
        source_url: Option<String>,
    ) -> PreprocessingResult {
        let page = html::Page::parse(self, html, source_url.as_deref());
        let (viable, reason) = self.check_viability(&page.text());
        if !viable {
            return rejected(reason);
        }
        let boiler: HashSet<String> = boilerplate.unwrap_or_default().into_iter().collect();
        let shortcodes = self.shortcode_names(&page.text());
        let blocks = page
            .blocks(&boiler)
            .into_iter()
            .filter_map(|b| match b.kind {
                Kind::Code => Some(b),
                kind => {
                    let text = self.refang(&self.strip_shortcodes(&b.text, &shortcodes));
                    text.chars().any(|c| c.is_alphanumeric()).then_some(Block { kind, text })
                }
            })
            .collect();
        self.finish(blocks)
    }
}

impl CtiEngine {
    /// Passes communes sur les blocs du contenu : doublons, métadonnées d'en-tête, rognage de la tête et de la queue,
    /// titres orphelins ; puis rendu et sections.
    fn finish(&self, blocks: Vec<Block>) -> PreprocessingResult {
        let mut blocks = blocks;

        // 1. Doublons exacts de blocs narratifs (répétitions de mise en page)
        let mut seen: HashSet<String> = HashSet::new();
        blocks.retain(|b| {
            if b.kind == Kind::Text && b.text.chars().count() >= 60 {
                seen.insert(b.text.clone())
            } else {
                true
            }
        });

        // 2. Métadonnées d'en-tête (date de publication, signature) : courtes, sans phrase, datées.
        //    La date reste disponible dans la base (`publication_date`) ; la signature d'un analyste
        //    ne doit jamais devenir une entité du graphe.
        let mut seen_blocks = 0usize;
        blocks.retain(|b| {
            seen_blocks += 1;
            let is_meta = seen_blocks <= 8
                && b.kind == Kind::Text
                && !b.text.contains('\n')
                && b.text.chars().count() < 100
                && !ends_sentence(&b.text)
                && self.re_date.is_match(&b.text);
            !is_meta
        });

        // 3. Rognage de la tête : fil d'Ariane, catégories, boutons avant le premier vrai contenu
        let mut trimmed: Vec<Block> = Vec::with_capacity(blocks.len());
        let mut in_head = true;
        for b in blocks {
            if in_head {
                match b.kind {
                    Kind::Heading(_) => {}
                    Kind::Text if !self.is_substantial(&b) && !ends_sentence(&b.text) => continue,
                    _ => in_head = false,
                }
            }
            trimmed.push(b);
        }
        let mut blocks = trimmed;

        // 4. Rognage de la queue : tags, auteurs, partage, articles liés après le dernier contenu réel
        while let Some(last) = blocks.last() {
            let weak = matches!(last.kind, Kind::Heading(_))
                || (last.kind == Kind::Text && !self.is_substantial(last));
            if weak {
                blocks.pop();
            } else {
                break;
            }
        }

        // 5. Titres orphelins (aucun contenu avant le titre suivant de même rang ou supérieur)
        let mut final_blocks: Vec<Block> = Vec::with_capacity(blocks.len());
        for (i, b) in blocks.iter().enumerate() {
            if let Kind::Heading(level) = b.kind {
                let orphan = match blocks.get(i + 1) {
                    None => true,
                    Some(Block { kind: Kind::Heading(next), .. }) => *next <= level,
                    _ => false,
                };
                if orphan {
                    continue;
                }
            }
            final_blocks.push(b.clone());
        }

        let clean_markdown = render(&final_blocks);
        if clean_markdown.chars().count() < MIN_VIABLE_CHARS {
            return rejected(Some("Contenu insuffisant après nettoyage".into()));
        }
        let sections = self.build_sections(&final_blocks);

        PreprocessingResult { is_processable: true, reject_reason: None, clean_markdown, sections }
    }

    /// Noms de shortcodes repérés par leurs attributs `clé=valeur` : `[Vendor]` ou `[0]` dans la prose ne sont jamais touchés.
    fn shortcode_names(&self, text: &str) -> HashSet<String> {
        self.re_shortcode
            .captures_iter(text)
            .filter(|c| c[1].is_empty() && c[3].contains('='))
            .map(|c| c[2].to_lowercase())
            .collect()
    }

    fn strip_shortcodes(&self, s: &str, names: &HashSet<String>) -> String {
        if names.is_empty() {
            return s.to_string();
        }
        let t = self.re_shortcode.replace_all(s, |c: &Captures| {
            if names.contains(&c[2].to_lowercase()) {
                String::new()
            } else {
                c[0].to_string()
            }
        });
        t.lines().map(|l| l.split_whitespace().collect::<Vec<_>>().join(" ")).collect::<Vec<_>>().join("\n")
    }

    fn is_technical(&self, line: &str) -> bool {
        is_code_like(line) || self.re_ioc_hint.is_match(line)
    }

    /// Dans le code, seules les neutralisations sans ambiguïté sont levées.
    fn refang_code(&self, code: &str) -> String {
        let t = self.re_hxxp.replace_all(code, "http$1");
        self.re_code_dot.replace_all(&t, "$1.$2").to_string()
    }

    /// Un bloc « substantiel » est du contenu réel : code, table, prose, ou texte portant des IOCs.
    fn is_substantial(&self, b: &Block) -> bool {
        match b.kind {
            Kind::Code | Kind::Table => true,
            Kind::Heading(_) => false,
            Kind::Text => {
                let n = b.text.chars().count();
                n >= 120 || (n >= 50 && ends_sentence(&b.text)) || self.re_ioc_hint.is_match(&b.text)
            }
        }
    }

    fn build_sections(&self, blocks: &[Block]) -> Vec<ArticleSection> {
        let mut sections: Vec<ArticleSection> = Vec::new();
        let mut stack: Vec<(u8, String)> = Vec::new();
        let mut title = String::new();
        let mut level = 0u8;
        let mut path = String::new();
        let mut body: Vec<&str> = Vec::new();

        let flush_section = |title: &str, level: u8, path: &str, body: &mut Vec<&str>, sections: &mut Vec<ArticleSection>| {
            if body.is_empty() {
                return;
            }
            let content = body.join("\n\n");
            let iocs = self.re_ioc_density.find_iter(&content).count();
            let lines = content.lines().filter(|l| !l.trim().is_empty()).count().max(1);
            sections.push(ArticleSection {
                section_index: sections.len(),
                title: title.to_string(),
                level,
                char_count: content.chars().count(),
                is_appendix_ioc: iocs >= 8 && iocs * 2 >= lines,
                heading_path: path.to_string(),
                blocks: body.iter().map(|s| s.to_string()).collect(),
                content,
            });
            body.clear();
        };

        for b in blocks {
            if let Kind::Heading(l) = b.kind {
                flush_section(&title, level, &path, &mut body, &mut sections);
                while stack.last().map_or(false, |(lv, _)| *lv >= l) {
                    stack.pop();
                }
                stack.push((l, b.text.clone()));
                path = stack.iter().map(|(_, t)| t.as_str()).collect::<Vec<_>>().join(" > ");
                title = b.text.clone();
                level = l;
            } else {
                body.push(&b.text);
            }
        }
        flush_section(&title, level, &path, &mut body, &mut sections);
        sections
    }
}

fn rejected(reason: Option<String>) -> PreprocessingResult {
    PreprocessingResult {
        is_processable: false,
        reject_reason: reason,
        clean_markdown: String::new(),
        sections: Vec::new(),
    }
}

fn render(blocks: &[Block]) -> String {
    let parts: Vec<String> = blocks
        .iter()
        .map(|b| match b.kind {
            Kind::Heading(l) => format!("{} {}", "#".repeat(l as usize), b.text),
            _ => b.text.clone(),
        })
        .collect();
    parts.join("\n\n").trim().to_string()
}

fn normalize_input(s: &str) -> String {
    s.replace("\r\n", "\n")
        .replace('\r', "\n")
        .chars()
        .filter(|c| {
            !matches!(
                c,
                '\u{200b}' | '\u{200c}' | '\u{200d}' | '\u{feff}' | '\u{2060}' | '\u{00ad}' | '\u{2800}'
            )
        })
        .map(|c| if c == '\u{a0}' || c == '\u{202f}' { ' ' } else { c })
        .collect()
}

fn fence_marker(t: &str) -> Option<&'static str> {
    if t.starts_with("```") {
        Some("```")
    } else if t.starts_with("~~~") {
        Some("~~~")
    } else {
        None
    }
}

fn parse_heading(line: &str) -> Option<(u8, String)> {
    if is_indented_code_line(line) {
        return None;
    }
    let t = line.trim();
    let n = t.chars().take_while(|c| *c == '#').count();
    if n == 0 || n > 6 {
        return None;
    }
    let rest = &t[n..];
    if rest.is_empty() || rest.starts_with(char::is_whitespace) {
        Some((n as u8, rest.trim().to_string()))
    } else {
        None
    }
}

fn flush(blocks: &mut Vec<Block>, cur: &mut Vec<&str>) {
    if cur.is_empty() {
        return;
    }
    let kind = if cur.iter().all(|l| l.trim_start().starts_with('|')) { Kind::Table } else { Kind::Text };
    blocks.push(Block { kind, text: cur.join("\n") });
    cur.clear();
}

fn setext_level(t: &str) -> Option<u8> {
    if t.len() >= 3 && t.chars().all(|c| c == '=') {
        Some(1)
    } else if t.len() >= 3 && t.chars().all(|c| c == '-') {
        Some(2)
    } else {
        None
    }
}

fn ends_with_list_item(b: &Block) -> bool {
    if b.kind != Kind::Text {
        return false;
    }
    let last = b.text.lines().last().unwrap_or("").trim_start();
    let digits = last.chars().take_while(|c| c.is_ascii_digit()).count();
    last.starts_with("* ")
        || last.starts_with("- ")
        || last.starts_with("+ ")
        || (digits > 0 && last[digits..].starts_with(". "))
}

fn is_indented_code_line(line: &str) -> bool {
    line.starts_with("    ") || line.starts_with('\t')
}

/// Phrase de prose : assez longue, terminée par une ponctuation, faite de mots, ni code ni liste ni table ni titre.
fn is_prose_sentence(line: &str) -> bool {
    let t = line.trim();
    if t.chars().count() < 60 || !ends_sentence(t) || is_code_like(t) || t.starts_with(['*', '-', '+', '|', '#', '>']) {
        return false;
    }
    let non_space = t.chars().filter(|c| !c.is_whitespace()).count().max(1);
    let alpha = t.chars().filter(|c| c.is_alphabetic()).count();
    alpha * 10 > non_space * 7
}

/// Découpage structurel : titres, blocs de code (clôturés ou indentés, atomiques), tables et paragraphes.
fn parse_blocks(text: &str) -> Vec<Block> {
    let lines: Vec<&str> = text.lines().collect();

    // Si les PHRASES du document sont indentées, l'indentation est un artefact de mise en forme, pas du code. Compter toutes
    // les lignes désactivait le code indenté des rapports riches en code (règles, journaux, configurations : plus de 60 % des
    // lignes), alors que leur prose est à la marge.
    let sentences = lines.iter().filter(|l| is_prose_sentence(l)).count();
    let indented_sentences = lines.iter().filter(|l| is_prose_sentence(l) && is_indented_code_line(l)).count();
    let allow_indented_code = sentences < 3 || indented_sentences * 10 <= sentences * 6;

    let mut blocks: Vec<Block> = Vec::new();
    let mut cur: Vec<&str> = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let t = line.trim();
        if let Some(marker) = fence_marker(t) {
            if let Some(off) = lines[i + 1..].iter().position(|l| l.trim().starts_with(marker)) {
                flush(&mut blocks, &mut cur);
                let end = i + 1 + off;
                blocks.push(Block { kind: Kind::Code, text: lines[i..=end].join("\n") });
                i = end + 1;
                continue;
            }
        }
        // Code indenté : démarre après une ligne vide (il n'interrompt pas un paragraphe) et ne suit
        // pas un item de liste (sinon c'est la suite indentée de l'item, donc de la prose).
        if allow_indented_code
            && cur.is_empty()
            && !t.is_empty()
            && is_indented_code_line(line)
            && !blocks.last().map_or(false, ends_with_list_item)
        {
            let mut end = i;
            let mut j = i;
            while j < lines.len() && (lines[j].trim().is_empty() || is_indented_code_line(lines[j])) {
                if !lines[j].trim().is_empty() {
                    end = j;
                }
                j += 1;
            }
            blocks.push(Block { kind: Kind::Code, text: lines[i..=end].join("\n") });
            i = end + 1;
            continue;
        }
        if let Some(level) = setext_level(t) {
            // `Titre` + `=====` / `-----` : titre setext (le soulignement suit immédiatement la ligne titre)
            if cur.len() == 1 && cur[0].trim().chars().count() <= 120 && !cur[0].trim_start().starts_with(['|', '*', '-', '+', '>']) {
                let title = cur.pop().unwrap().trim().to_string();
                flush(&mut blocks, &mut cur);
                blocks.push(Block { kind: Kind::Heading(level), text: title });
                i += 1;
                continue;
            }
        }
        if t.is_empty() {
            flush(&mut blocks, &mut cur);
        } else if let Some((level, title)) = parse_heading(line) {
            flush(&mut blocks, &mut cur);
            blocks.push(Block { kind: Kind::Heading(level), text: title });
        } else {
            cur.push(line);
        }
        i += 1;
    }
    flush(&mut blocks, &mut cur);
    blocks
}

/// Ligne de configuration, de code ou de séparateur : ne jamais l'apprendre comme gabarit
/// (elle reviendrait légitimement d'un article à l'autre, ex. config Cobalt Strike, règle YARA).
fn is_code_like(line: &str) -> bool {
    if ["{", "}", ";", "=", "\":", "/*", "*/", "\\", "$", "::"].iter().any(|m| line.contains(m)) {
        return true;
    }
    let non_space = line.chars().filter(|c| !c.is_whitespace()).count().max(1);
    let alpha = line.chars().filter(|c| c.is_alphabetic()).count();
    alpha * 2 < non_space
}

fn ends_sentence(s: &str) -> bool {
    s.trim_end().ends_with(['.', '!', '?', '。'])
}

fn extract_root_domain(url: &str) -> Option<String> {
    let host = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?
        .split('/')
        .next()?
        .split(':')
        .next()?
        .to_lowercase();
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() >= 2 {
        Some(format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]))
    } else {
        Some(host)
    }
}

/// Lien interne : chemin relatif, ancre de page, ou domaine de l'éditeur lui-même.
fn is_internal(url: &str, root: Option<&str>) -> bool {
    let u = url.trim().to_lowercase();
    u.starts_with('/')
        || u.starts_with('#')
        || u.starts_with("mailto:")
        || u.starts_with("javascript:")
        || root.map_or(false, |r| u.contains(r))
}

#[pymodule]
fn cti_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<CtiEngine>()?;
    m.add_class::<PreprocessingResult>()?;
    m.add_class::<ArticleSection>()?;
    m.add_class::<Chunk>()?;
    m.add_class::<MdBlock>()?;
    Ok(())
}

#[cfg(test)]
mod tests;
