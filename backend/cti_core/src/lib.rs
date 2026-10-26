//! Moteur déterministe de preprocessing CTI.
//!
//! Principes :
//! - purement syntaxique : aucune liste d'acteurs, d'outils ou d'éditeurs en dur ;
//! - le bruit est détecté par structure (densité de liens, position en tête/queue de document)
//!   et par apprentissage du gabarit de chaque site sur le corpus (`learn_boilerplate`) ;
//! - les blocs de code et les tables sont atomiques : jamais déplacés, jamais tronqués ;
//! - aucune extraction d'entités ni d'IOCs : les IOCs restent dans leur contexte narratif.

use pyo3::prelude::*;
use regex::{Captures, Regex};
use std::collections::{HashMap, HashSet};

const MIN_VIABLE_CHARS: usize = 200;
/// Un document court contenant une de ces signatures est une page d'erreur de scraping.
const ERROR_PAGE_MAX_CHARS: usize = 1500;
/// Le gabarit d'un site (menus, bannières, pieds de page) vit en tête et en queue de document.
const TEMPLATE_HEAD_LINES: usize = 15;
const TEMPLATE_TAIL_LINES: usize = 30;

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
    re_source_url: Regex,
    re_error_page: Regex,
    re_img: Regex,
    re_img_paren: Regex,
    re_footnote: Regex,
    re_md_link: Regex,
    re_bare_paren: Regex,
    re_shortcode: Regex,
    re_ui_controls: Regex,
    re_hxxp: Regex,
    re_dot: Regex,
    re_at: Regex,
    re_code_dot: Regex,
    re_half_dot: Regex,
    re_escape: Regex,
    re_stars: Regex,
    re_trailing_spaces: Regex,
    re_inner_spaces: Regex,
    re_hex_hash: Regex,
    re_ioc_hint: Regex,
    re_ioc_density: Regex,
    re_date: Regex,
    re_bold_title: Regex,
    re_setext: Regex,
    re_glue_before: Regex,
    re_glue_after: Regex,
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
            re_source_url: rx(r"(?im)^-\s*\*\*URL\s*:\*\*\s*(https?://\S+)"),
            re_error_page: rx(
                r"(?i)access denied|403 forbidden|404 not found|page not found|just a moment|checking your browser|enable javascript|captcha|attention required|service unavailable|too many requests|are you a robot|verify you are human",
            ),
            re_img: rx(r"!\[[^\]]*\]\([^)]*\)"),
            // Variante dégénérée produite par certains scrapers : `!(https://…/img.png)`
            re_img_paren: rx(r"!\([^)]*\)"),
            re_footnote: rx(r"\[\[\d+\]\]\([^)]*\)"),
            re_md_link: rx(r#"\[([^\]]*)\]\(\s*([^)\s]*)(?:\s+"[^"]*")?\s*\)"#),
            // Lien dont l'ancre a été perdue au scraping : `(https://…)` ou `(/chemin/relatif)`
            re_bare_paren: rx(r#"\(\s*(https?://[^)\s]+|/[^)\s]*)(?:\s+"[^"]*")?\s*\)"#),
            re_shortcode: rx(r"\[(/?)([A-Za-z][\w:-]*)((?:\s[^\]]*)?)\]"),
            re_ui_controls: rx(
                r"(?i)^(play video|play|pause|mute|current time.*|duration.*|loaded:.*|progress:.*|stream type.*|remaining time.*|playback rate.*|chapters|descriptions|captions|audio track|fullscreen|this is a modal window.*|beginning of dialog window.*|textcolor.*|font size.*|reset restore all.*|close modal dialog|end of dialog window.*|seek slider.*|volume-slider.*|\d+s \d+s|_00:00_.*|video|podcast|×)$",
            ),
            re_hxxp: rx(r"(?i)hxxp(s?)"),
            re_dot: rx(r"(?i)[\[\(\{]\s*(?:\.|dot)\s*[\]\)\}]"),
            re_at: rx(r"(?i)[\[\(\{]\s*(?:@|at)\s*[\]\)\}]"),
            re_code_dot: rx(r"(\w)\[\.\](\w)"),
            // Neutralisations « à moitié fermées » : `domaine.]com`, `domaine[.com`
            re_half_dot: rx(r"(\w)(?:\.\]|\[\.)(\w)"),
            re_escape: rx(r"\\([._\-])"),
            re_stars: rx(r"\*{4,}"),
            re_trailing_spaces: rx(r"(?m)(\S) {2,}$"),
            re_inner_spaces: rx(r"(\S) {2,}"),
            re_hex_hash: rx(r"[a-fA-F0-9]{32,}"),
            re_ioc_hint: rx(
                r"(?i)\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|\b[a-f0-9]{32,64}\b|https?://|\bCVE-\d{4}-\d{4,7}\b",
            ),
            // Ligne entièrement en gras : titre implicite très courant sur les pages scrapées
            re_bold_title: rx(r"^\s*(?:\*\*|__)\s*([^*_`\n]{2,90}?)\s*(?:\*\*|__)\s*:?\s*$"),
            re_setext: rx(r"^\s*(=|-){3,}\s*$"),
            re_date: rx(
                r"(?i)\b(?:19|20)\d{2}[-/.]\d{1,2}[-/.]\d{1,2}\b|\b\d{1,2}[-/.]\d{1,2}[-/.](?:19|20)\d{2}\b|\b(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.? \d{1,2}(?:st|nd|rd|th)?,? (?:19|20)\d{2}\b|\b\d{1,2}(?:st|nd|rd|th)? (?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]* (?:19|20)\d{2}\b",
            ),
            // Le scraping colle parfois l'ancre au mot voisin : `about[Lien](url)` / `[Lien](url)suite`
            re_glue_before: rx(r"([A-Za-z0-9])(\[[^\]]*\]\()"),
            re_glue_after: rx(r#"(\]\([^)\s]*(?:\s+"[^"]*")?\))([A-Za-z0-9])"#),
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

    /// Forme canonique d'une ligne (minuscules, chiffres → 0, liens dépliés) : clé de comparaison du gabarit.
    pub fn normalize_line(&self, line: &str) -> String {
        self.norm_line(line)
    }

    /// Fast-reject : articles vides, coquilles et pages d'erreur de scraping.
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

    /// Apprend le gabarit d'un site : lignes (normalisées) présentes dans au moins
    /// `max(min_docs, min_ratio × N)` des documents fournis. Aucune liste en dur : le
    /// corpus lui-même désigne les menus, bannières, pieds de page et appels à l'action.
    pub fn learn_boilerplate(&self, docs: Vec<String>, min_docs: usize, min_ratio: f64) -> Vec<String> {
        let n = docs.len();
        if n == 0 {
            return Vec::new();
        }
        let threshold = min_docs.max((min_ratio * n as f64).ceil() as usize);
        let mut counts: HashMap<String, usize> = HashMap::new();
        for doc in &docs {
            let mut seen: HashSet<String> = HashSet::new();
            let blocks = parse_blocks(&normalize_input(doc));
            let eligible = self.template_eligibility(&blocks);
            for (bi, b) in blocks.iter().enumerate() {
                if b.kind != Kind::Text {
                    continue;
                }
                for (li, line) in b.text.lines().enumerate() {
                    if !eligible[bi][li] {
                        continue;
                    }
                    let norm = self.norm_line(line);
                    let len = norm.chars().count();
                    if (4..=400).contains(&len) {
                        seen.insert(norm);
                    }
                }
            }
            for s in seen {
                *counts.entry(s).or_insert(0) += 1;
            }
        }
        let mut out: Vec<String> = counts
            .into_iter()
            .filter(|(_, c)| *c >= threshold)
            .map(|(l, _)| l)
            .collect();
        out.sort();
        out
    }

    #[pyo3(signature = (raw_markdown, boilerplate=None, source_url=None))]
    pub fn process_article(
        &self,
        raw_markdown: &str,
        boilerplate: Option<Vec<String>>,
        source_url: Option<String>,
    ) -> PreprocessingResult {
        let (viable, reason) = self.check_viability(raw_markdown);
        if !viable {
            return rejected(reason);
        }

        let text = normalize_input(raw_markdown);
        let publisher_root = source_url
            .as_deref()
            .and_then(extract_root_domain)
            .or_else(|| {
                self.re_source_url
                    .captures(&text)
                    .and_then(|c| c.get(1))
                    .and_then(|m| extract_root_domain(m.as_str()))
            });
        let root = publisher_root.as_deref();
        let boiler: HashSet<String> = boilerplate.unwrap_or_default().into_iter().collect();
        let shortcode_names = self.collect_shortcode_names(&text);

        // 1. Nettoyage bloc par bloc (le code et les tables ne sont jamais déplacés)
        let mut blocks: Vec<Block> = Vec::new();
        let mut last_real_level = 1u8;
        let parsed = parse_blocks(&text);
        let eligible = if boiler.is_empty() { Vec::new() } else { self.template_eligibility(&parsed) };
        for (bi, b) in parsed.into_iter().enumerate() {
            match b.kind {
                Kind::Code => blocks.push(Block { kind: Kind::Code, text: self.refang_code(&b.text) }),
                Kind::Table => {
                    let cleaned: Vec<String> = b
                        .text
                        .lines()
                        .map(|l| self.inline_clean(l, root, &shortcode_names, false))
                        .collect();
                    blocks.push(Block { kind: Kind::Table, text: cleaned.join("\n") });
                }
                Kind::Heading(level) => {
                    last_real_level = level;
                    let title = self.inline_clean(&b.text, root, &shortcode_names, true);
                    let title = title.trim().trim_matches('*').trim().to_string();
                    if title.chars().any(|c| c.is_alphanumeric()) {
                        blocks.push(Block { kind: Kind::Heading(level), text: title });
                    }
                }
                Kind::Text => {
                    let lines: Vec<&str> = b
                        .text
                        .lines()
                        .enumerate()
                        .filter(|(li, l)| {
                            !(eligible.get(bi).map_or(false, |f| f[*li]) && boiler.contains(&self.norm_line(l)))
                        })
                        .map(|(_, l)| l)
                        .filter(|l| !self.re_ui_controls.is_match(l.trim()))
                        .collect();
                    if lines.is_empty() {
                        continue;
                    }
                    let raw = lines.join("\n");
                    if let Some(title) = self.pseudo_heading(&raw) {
                        let level = (last_real_level + 1).min(6);
                        let title = self.inline_clean(&title, root, &shortcode_names, true);
                        if title.chars().any(|c| c.is_alphanumeric()) {
                            blocks.push(Block { kind: Kind::Heading(level), text: title.trim().to_string() });
                        }
                        continue;
                    }
                    if self.is_nav_block(&raw, root) {
                        continue;
                    }
                    let cleaned = self.inline_clean(&raw, root, &shortcode_names, true);
                    if cleaned.chars().any(|c| c.is_alphanumeric()) {
                        blocks.push(Block { kind: Kind::Text, text: cleaned });
                    }
                }
            }
        }

        // 2. Doublons exacts de blocs narratifs (répétitions de scraping)
        let mut seen: HashSet<String> = HashSet::new();
        blocks.retain(|b| {
            if b.kind == Kind::Text && b.text.chars().count() >= 60 {
                seen.insert(b.text.clone())
            } else {
                true
            }
        });

        // 2b. Métadonnées d'en-tête (date de publication, signature) : courtes, sans phrase, datées.
        //     La date reste disponible dans la base (`publication_date`) ; la signature d'un analyste
        //     ne doit jamais devenir une entité du graphe.
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
}

impl CtiEngine {
    /// Forme canonique d'une ligne pour comparer le gabarit entre articles d'un même site.
    fn norm_line(&self, line: &str) -> String {
        let t = self.re_md_link.replace_all(line, "$1");
        let t = self.re_bare_paren.replace_all(&t, "");
        let t: String = t
            .to_lowercase()
            .trim_start_matches(|c: char| "*-•>+# ".contains(c))
            .chars()
            .map(|c| if c.is_ascii_digit() { '0' } else { c })
            .collect();
        t.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// Un paragraphe d'une seule ligne, entièrement en gras, sans ponctuation de phrase ni donnée
    /// technique, est un titre implicite (« **Step 2 – Persistence** »).
    fn pseudo_heading(&self, raw: &str) -> Option<String> {
        if raw.contains('\n') {
            return None;
        }
        let title = self.re_bold_title.captures(raw)?.get(1)?.as_str().trim().to_string();
        let title = title.trim_end_matches(':').trim().to_string();
        if title.is_empty() || ends_sentence(&title) || title.ends_with('?') || self.is_technical(&title) {
            return None;
        }
        Some(title)
    }

    fn is_technical(&self, line: &str) -> bool {
        // Les URL de liens Markdown ne comptent pas : seule la partie visible de la ligne est jugée.
        let visible = self.re_md_link.replace_all(line, "$1");
        let visible = self.re_bare_paren.replace_all(&visible, "");
        is_code_like(&visible) || self.re_ioc_hint.is_match(&visible)
    }

    /// Pour chaque ligne de chaque bloc : peut-elle être du gabarit de site ? Oui seulement si elle
    /// est en fenêtre de tête/queue, ne porte ni code ni IOC, ne touche aucune ligne technique
    /// et n'est pas une ligne de table. Garde-fou : jamais de commande, règle YARA ou mapping ATT&CK.
    fn template_eligibility(&self, blocks: &[Block]) -> Vec<Vec<bool>> {
        let total: usize = blocks
            .iter()
            .filter(|b| b.kind == Kind::Text)
            .map(|b| b.text.lines().filter(|l| !l.trim().is_empty()).count())
            .sum();
        let mut idx = 0usize;
        let mut out: Vec<Vec<bool>> = Vec::with_capacity(blocks.len());
        for b in blocks {
            if b.kind != Kind::Text {
                out.push(Vec::new());
                continue;
            }
            let lines: Vec<&str> = b.text.lines().collect();
            let tech: Vec<bool> = lines.iter().map(|l| self.is_technical(l)).collect();
            let mut flags = Vec::with_capacity(lines.len());
            for (j, l) in lines.iter().enumerate() {
                if l.trim().is_empty() {
                    flags.push(false);
                    continue;
                }
                let in_window = idx < TEMPLATE_HEAD_LINES || idx + TEMPLATE_TAIL_LINES >= total;
                idx += 1;
                let near_tech = (j > 0 && tech[j - 1]) || (j + 1 < lines.len() && tech[j + 1]);
                flags.push(in_window && !tech[j] && !near_tech && !l.trim_start().starts_with('|'));
            }
            out.push(flags);
        }
        out
    }

    /// Noms de shortcodes (ex. constructeurs de pages WordPress) repérés par leurs attributs `clé=valeur`.
    fn collect_shortcode_names(&self, text: &str) -> HashSet<String> {
        let mut names = HashSet::new();
        for c in self.re_shortcode.captures_iter(text) {
            if c[1].is_empty() && c[3].contains('=') {
                names.insert(c[2].to_lowercase());
            }
        }
        names
    }

    fn strip_shortcodes(&self, s: &str, names: &HashSet<String>) -> String {
        if names.is_empty() {
            return s.to_string();
        }
        self.re_shortcode
            .replace_all(s, |c: &Captures| {
                if names.contains(&c[2].to_lowercase()) {
                    String::new()
                } else {
                    c[0].to_string()
                }
            })
            .to_string()
    }

    /// Dans le code, seules les neutralisations sans ambiguïté sont levées.
    fn refang_code(&self, code: &str) -> String {
        let t = self.re_hxxp.replace_all(code, "http$1");
        self.re_code_dot.replace_all(&t, "$1.$2").to_string()
    }

    fn inline_clean(&self, s: &str, root: Option<&str>, names: &HashSet<String>, collapse: bool) -> String {
        let mut t = self.re_img.replace_all(s, "").to_string();
        t = self.re_img_paren.replace_all(&t, "").to_string();
        t = self.re_footnote.replace_all(&t, "").to_string();
        t = self.re_glue_before.replace_all(&t, "$1 $2").to_string();
        t = self.re_glue_after.replace_all(&t, "$1 $2").to_string();
        t = self
            .re_md_link
            .replace_all(&t, |c: &Captures| self.unwrap_link(&c[1], &c[2], root))
            .to_string();
        t = self
            .re_bare_paren
            .replace_all(&t, |c: &Captures| {
                if is_internal(&c[1], root) {
                    String::new()
                } else {
                    c[1].to_string()
                }
            })
            .to_string();
        t = self.strip_shortcodes(&t, names);
        t = self.refang(&t);
        t = self.re_escape.replace_all(&t, "$1").to_string();
        t = t
            .replace("&nbsp;", " ")
            .replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&#39;", "'");
        t = self.re_stars.replace_all(&t, "").to_string();
        if collapse {
            t = self.re_trailing_spaces.replace_all(&t, "$1").to_string();
            t = self.re_inner_spaces.replace_all(&t, "$1 ").to_string();
        }
        t
    }

    /// `[ancre](url)` -> ancre. L'URL n'est conservée que si l'ancre est elle-même une URL externe,
    /// ou si l'URL externe embarque un condensat (lien vers un échantillon).
    fn unwrap_link(&self, anchor: &str, url: &str, root: Option<&str>) -> String {
        let a = anchor.trim();
        let internal = is_internal(url, root);
        if a.is_empty() {
            return String::new();
        }
        if a == url || a.starts_with("http") {
            return if internal { String::new() } else { a.to_string() };
        }
        if !internal && self.re_hex_hash.is_match(url) {
            return format!("{} ({})", a, url);
        }
        a.to_string()
    }

    /// Bloc de navigation : majoritairement des liens, quasiment pas de prose, liens internes
    /// ou sans ancre (menus, tags, articles liés), ou teaser tronqué par « … » avec lien interne.
    fn is_nav_block(&self, raw: &str, root: Option<&str>) -> bool {
        // Les cartes `[ ![img](…) Titre ](url)` portent des `]` imbriqués : on retire les images d'abord.
        let raw = self.re_img.replace_all(raw, "");
        let raw = self.re_img_paren.replace_all(&raw, "");
        let raw: &str = &raw;
        let mut link_chars = 0usize;
        let mut links = 0usize;
        let mut internal = 0usize;

        for c in self.re_md_link.captures_iter(raw) {
            let (a, u) = (c[1].trim(), &c[2]);
            // Une liste de liens dont l'ancre est un IOC (CVE, hash, IP…) est du contenu, jamais de la navigation.
            if self.re_ioc_hint.is_match(a) {
                return false;
            }
            if a == u || a.starts_with("http") {
                continue;
            }
            links += 1;
            link_chars += c[0].len();
            if is_internal(u, root) {
                internal += 1;
            }
        }
        for c in self.re_bare_paren.captures_iter(raw) {
            links += 1;
            link_chars += c[0].len();
            if is_internal(&c[1], root) {
                internal += 1;
            }
        }
        if links == 0 {
            return false;
        }

        let rest = self.re_md_link.replace_all(raw, "");
        let rest = self.re_bare_paren.replace_all(&rest, "");
        let words = rest
            .split_whitespace()
            .filter(|w| w.chars().any(|c| c.is_alphanumeric()))
            .count();
        let density = link_chars as f64 / raw.len().max(1) as f64;
        let mostly_internal = internal * 10 >= links * 7;

        let trimmed = raw.trim_end();
        let teaser = (trimmed.ends_with('…') || trimmed.ends_with("...")) && internal > 0;

        (density >= 0.5 && words < 25 && mostly_internal) || teaser
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
mod tests {
    use super::*;

    fn pad_n(n: usize) -> String {
        let tag: String = (0..4).map(|k| (b'a' + ((n / 3usize.pow(k)) % 3) as u8 + 3 * k as u8) as char).collect();
        format!("Ce paragraphe {tag} de remplissage décrit longuement le déroulement de l'intrusion observée sur l'hôte {tag}. ").repeat(2)
    }

    fn pad() -> String {
        pad_n(0)
    }

    fn run(body: &str) -> String {
        let doc = format!("# Titre\n\n{}\n\n{}\n", pad(), body);
        CtiEngine::new().process_article(&doc, None, None).clean_markdown
    }

    #[test]
    fn link_anchor_survives() {
        let out = run("Le groupe [Lazarus Group](https://attack.mitre.org/groups/G0032/) a déployé [CrowdStrike Counter Adversary Operations](https://www.crowdstrike.com/x/) outils.");
        assert!(out.contains("Le groupe Lazarus Group a déployé CrowdStrike Counter Adversary Operations outils."), "{out}");
    }

    #[test]
    fn bracketed_technical_tokens_survive() {
        let out = run("Le stager lit la valeur [IntPtr] puis [Parameter] et l'offset [0] dans [ID].");
        assert!(out.contains("[IntPtr] puis [Parameter] et l'offset [0] dans [ID]"), "{out}");
    }

    #[test]
    fn code_blocks_are_untouched() {
        let code = "```powershell\n[Parameter(Mandatory)] param($a)\n$x = $a[0]  # [i] kept\nhxxp://evil[.]com/a\n```";
        let out = run(code);
        assert!(out.contains("[Parameter(Mandatory)] param($a)\n$x = $a[0]  # [i] kept"), "{out}");
        assert!(out.contains("http://evil.com/a"), "{out}");
    }

    #[test]
    fn refang_variants() {
        let e = CtiEngine::new();
        assert_eq!(e.refang("hxxps[:]//bad[.]site/a"), "https://bad.site/a");
        assert_eq!(e.refang("hXXp://a(.)b"), "http://a.b");
        assert_eq!(e.refang("user[at]x[dot]com"), "user@x.com");
        assert_eq!(e.refang("192[.]168[.]1[.]5"), "192.168.1.5");
    }

    #[test]
    fn wordpress_shortcodes_removed_but_not_prose() {
        let out = run("[et_pb_text _builder_version=\"4.2\"]Contenu réel de l'article décrivant la charge utile, avec [Vendor] conservé dans le texte.[/et_pb_text]");
        assert!(out.contains("avec [Vendor] conservé dans le texte."), "{out}");
        assert!(!out.contains("et_pb_text"), "{out}");
    }

    #[test]
    fn trailing_navigation_is_trimmed() {
        let out = run("## Conclusion\n\nLes acteurs de la menace abusent de services légitimes pour héberger leurs charges utiles et exfiltrer des données.\n\n## Article tags\n\n  * (/blog/tag/research/)\n  * (/blog/tag/labs/)\n");
        assert!(out.contains("Conclusion"), "{out}");
        assert!(!out.contains("Article tags"), "{out}");
        assert!(!out.contains("/blog/tag"), "{out}");
    }

    #[test]
    fn leading_breadcrumbs_are_trimmed() {
        let doc = format!("Threat Intelligence\n\nSubscribeRSS\n\n# Vrai titre\n\nMay 26, 2026\n\n{}\n", pad());
        let out = CtiEngine::new().process_article(&doc, None, None).clean_markdown;
        assert!(out.starts_with("# Vrai titre"), "{out}");
        assert!(!out.contains("SubscribeRSS"), "{out}");
    }

    #[test]
    fn ioc_lists_stay_in_place() {
        let out = run("## Indicateurs\n\n  * 185.220.101.4\n  * 2f4a8d3c9b1e7f6a5d4c3b2a19087766\n\n## Suite\n\nLa suite de l'analyse détaille la persistance mise en place par l'acteur sur les hôtes compromis du réseau.");
        let i = out.find("185.220.101.4").expect("ioc");
        let j = out.find("## Suite").expect("suite");
        assert!(i < j, "{out}");
    }

    #[test]
    fn learned_boilerplate_is_removed() {
        let e = CtiEngine::new();
        let docs: Vec<String> = (0..10)
            .map(|i| format!("# Article {i}\n\n{}\n\nSubscribe to our weekly threat digest today\n", pad_n(i + 1)))
            .collect();
        let learned = e.learn_boilerplate(docs.clone(), 5, 0.2);
        assert!(learned.iter().any(|l| l.contains("subscribe to our weekly")), "{learned:?}");
        let out = e.process_article(&docs[0], Some(learned), None).clean_markdown;
        assert!(!out.contains("weekly threat digest"), "{out}");
        assert!(out.contains("intrusion"), "{out}");
    }

    #[test]
    fn image_cards_are_navigation() {
        let card = "[ ![Titre voisin](https://cdn.exemple.com/i.png?w=1&h=2) Veille | Sep 15, 2026 Titre voisin ](/blog/titre-voisin/)";
        let out = run(&format!("## Related Content\n\n{card}\n"));
        assert!(!out.contains("Related Content"), "{out}");
        assert!(!out.contains("Titre voisin"), "{out}");
    }

    #[test]
    fn glued_defanged_schemes() {
        let e = CtiEngine::new();
        assert_eq!(e.refang("_hxxps://a.b/c_ et byhxxp://x"), "_https://a.b/c_ et byhttp://x");
    }

    #[test]
    fn code_like_lines_are_never_learned() {
        let e = CtiEngine::new();
        let docs: Vec<String> = (0..10)
            .map(|i| format!("# T{i}\n\n\"jitter\": 20,\n\n{}\n", pad_n(i + 1)))
            .collect();
        assert!(e.learn_boilerplate(docs, 5, 0.2).iter().all(|l| !l.contains("jitter")));
    }

    #[test]
    fn glued_anchor_gets_spaces() {
        let out = run("Pour en savoir plus sur[CrowdStrike Counter Adversary Operations](https://www.crowdstrike.com/x/)menaces et leurs opérateurs observés dans cette campagne de longue durée.");
        assert!(out.contains("sur CrowdStrike Counter Adversary Operations menaces"), "{out}");
    }

    #[test]
    fn link_lines_can_be_learned_as_template() {
        let e = CtiEngine::new();
        let cta = "  * _Tune in to the[Adversary Universe podcast](https://www.crowdstrike.com/pod/), where actors are revealed._";
        let docs: Vec<String> = (0..10).map(|i| format!("# T{i}\n\n{}\n\n{cta}\n", pad_n(i + 1))).collect();
        let learned = e.learn_boilerplate(docs.clone(), 5, 0.4);
        assert!(learned.iter().any(|l| l.contains("adversary universe podcast")), "{learned:?}");
    }

    #[test]
    fn byline_and_date_are_dropped_in_header() {
        let doc = format!("# Titre\n\nBy: Jane Analyst 2026/07/24 Read time: ( words)\n\nMay 26, 2026\n\n{}\n", pad());
        let out = CtiEngine::new().process_article(&doc, None, None).clean_markdown;
        assert!(!out.contains("Jane Analyst") && !out.contains("May 26"), "{out}");
    }

    #[test]
    fn cve_lists_with_internal_links_are_content() {
        let out = run("## Exploits\n\n  * [CVE-2023-39780](https://threatvault.exemple.com/?query=CVE-2023-39780)\n  * [CVE-2025-34037](https://threatvault.exemple.com/?query=CVE-2025-34037)\n\n## Suite\n\nLa suite de l'analyse décrit comment les opérateurs ont ensuite enchaîné ces vulnérabilités sur le parc.");
        assert!(out.contains("CVE-2023-39780") && out.contains("CVE-2025-34037"), "{out}");
    }

    #[test]
    fn indented_code_is_atomic_and_never_a_heading() {
        let out = run("Voici la sortie :\n\n    ## Observations: 1\n    ## $ fingerprint <chr> \"1669feb358ef7bc13fb28915c95b8a315770ed67\"\n    \n    curl -i -k https://172.30.132.194:9251/x -X POST\n\nSuite du récit de l'intrusion qui détaille la découverte du service exposé sur le réseau.");
        assert!(out.contains("1669feb358ef7bc13fb28915c95b8a315770ed67") && out.contains("172.30.132.194:9251"), "{out}");
        assert!(!out.contains("\n## Observations"), "{out}");
    }

    #[test]
    fn code_heavy_report_keeps_its_indented_code() {
        // Plus de 60 % des lignes sont indentées (une règle YARA), mais la prose est à la marge : le code reste du code.
        let rule = (0..30).map(|i| format!("          $s{i} = \"chaine{i}\" fullword ascii")).collect::<Vec<_>>().join("\n");
        let text = format!("## YARA\n\nLes règles suivantes détectent les fichiers déposés par l'opérateur lors de l'intrusion.\n\n    rule demo {{\n       strings:\n{rule}\n       condition:\n          all of them\n    }}\n");
        let kinds: Vec<String> = CtiEngine::new().split_blocks(&text).into_iter().map(|b| b.kind).collect();
        assert_eq!(kinds, vec!["heading", "text", "code"], "{text}");
    }

    #[test]
    fn indented_prose_is_a_layout_artifact_not_code() {
        let para = "    L'opérateur a déployé un chargeur sur le poste de travail compromis après l'ouverture du document.";
        let text = format!("{para}\n\n{para}\n\n{para}\n\n{para}\n");
        let kinds: Vec<String> = CtiEngine::new().split_blocks(&text).into_iter().map(|b| b.kind).collect();
        assert!(kinds.iter().all(|k| k == "text"), "{kinds:?}");
    }

    #[test]
    fn indented_continuation_of_list_item_is_prose() {
        let out = run("  * Première étape de la chaîne d'infection observée\n\n    Déployez [ThreatSonar](https://teamt5.org/produit/) pour détecter et bloquer cette activité sur les postes.\n\n## Suite\n\nLa suite du rapport décrit l'impact final sur les serveurs de fichiers et les sauvegardes du réseau.");
        assert!(out.contains("Déployez ThreatSonar pour détecter"), "{out}");
    }

    #[test]
    fn bold_only_lines_become_subheadings_with_path() {
        let doc = format!("# Rapport\n\n{}\n\n## Chaîne d'attaque\n\n**Step 2 – Persistance**\n\n{}\n\n**Cette phrase en gras se termine par un point.**\n\n{}\n", pad_n(1), pad_n(2), pad_n(3));
        let r = CtiEngine::new().process_article(&doc, None, None);
        let paths: Vec<_> = r.sections.iter().map(|s| s.heading_path.as_str()).collect();
        assert!(paths.contains(&"Rapport > Chaîne d'attaque > Step 2 – Persistance"), "{paths:?}");
        assert!(r.clean_markdown.contains("**Cette phrase en gras se termine par un point.**") || r.clean_markdown.contains("Cette phrase en gras"), "{}", r.clean_markdown);
    }

    #[test]
    fn setext_headings() {
        let r = CtiEngine::new().process_article(&format!("Titre principal\n===============\n\n{}\n\nSous-titre\n----------\n\n{}\n", pad_n(1), pad_n(2)), None, None);
        let t: Vec<_> = r.sections.iter().map(|s| (s.level, s.title.as_str())).collect();
        assert_eq!(t, vec![(1, "Titre principal"), (2, "Sous-titre")]);
    }

    #[test]
    fn half_closed_defang() {
        let e = CtiEngine::new();
        assert_eq!(e.refang("llc-image-ico.]click et evil[.com"), "llc-image-ico.click et evil.com");
    }

    #[test]
    fn sections_expose_atomic_blocks() {
        let r = CtiEngine::new().process_article(&format!("# T\n\n{}\n\n```\na\n\nb\n```\n", pad_n(1)), None, None);
        let blocks = &r.sections[0].blocks;
        assert_eq!(blocks.len(), 2, "{blocks:?}");
        assert!(blocks[1].starts_with("```") && blocks[1].contains("a\n\nb"));
    }

    #[test]
    fn chunks_never_split_code_or_orphan_a_heading() {
        let e = CtiEngine::new();
        let code = format!("```\n{}\n\n{}\n```", "x".repeat(300), "y".repeat(300));
        let md = format!("# T\n\n{}\n\n## Étape\n\n{}\n\n## Fin\n\n{}", pad_n(1), code, pad_n(2));
        let chunks = e.chunk_markdown(&md, 700);
        assert!(chunks.len() >= 2, "{chunks:?}");
        for c in &chunks {
            assert_eq!(c.text.matches("```").count() % 2, 0, "bloc de code coupé : {}", c.text);
            assert!(!c.text.trim_end().ends_with("## Fin") && !c.text.trim_end().ends_with("## Étape"), "titre orphelin : {}", c.text);
        }
        let rebuilt: String = chunks.iter().map(|c| c.text.clone()).collect::<Vec<_>>().join("\n\n");
        assert_eq!(rebuilt, md, "le découpage doit être sans perte ni duplication");
        assert!(chunks.iter().any(|c| c.heading_path == "T > Étape"), "{:?}", chunks.iter().map(|c| &c.heading_path).collect::<Vec<_>>());
    }

    #[test]
    fn split_blocks_keeps_order_kinds_and_heading_paths() {
        let md = format!("# T\n\n{}\n\n## A\n\n```\nx\n\ny\n```\n\n| a | b |\n| - | - |\n\n### B\n\n{}", pad_n(1), pad_n(2));
        let blocks = CtiEngine::new().split_blocks(&md);
        let shape: Vec<_> = blocks.iter().map(|b| (b.kind.as_str(), b.heading_path.as_str())).collect();
        assert_eq!(
            shape,
            vec![("heading", "T"), ("text", "T"), ("heading", "T > A"), ("code", "T > A"), ("table", "T > A"), ("heading", "T > A > B"), ("text", "T > A > B")]
        );
        assert!(blocks[3].text.contains("x\n\ny"));
    }

    #[test]
    fn fast_reject() {
        let e = CtiEngine::new();
        assert!(!e.check_viability("").0);
        assert!(!e.check_viability("trop court").0);
        let err = format!("Access Denied {}", "x ".repeat(150));
        assert!(!e.check_viability(&err).0);
        assert!(e.check_viability(&pad()).0);
    }

    #[test]
    fn sections_are_indexed_in_order() {
        let r = CtiEngine::new().process_article(
            &format!("# T\n\n{}\n\n## A\n\n{}\n\n### B\n\n{}\n", pad_n(1), pad_n(2), pad_n(3)),
            None,
            None,
        );
        let titles: Vec<_> = r.sections.iter().map(|s| (s.section_index, s.level, s.title.as_str())).collect();
        assert_eq!(titles, vec![(0, 1, "T"), (1, 2, "A"), (2, 3, "B")]);
    }
}
