//! Page HTML brute -> blocs du Markdown canonique (titres `#`, paragraphes, listes `- `, code clôturé, tables `|`).
//!
//! Le DOM porte ce qu'un export Markdown perdait : ce qui est un lien et où il pointe, ce qui est du code, une table,
//! un titre, un élément caché. Rien n'est propre à un éditeur ; le bruit est reconnu par structure :
//! - éléments jamais lus (scripts, formulaires, navigation, médias) et éléments cachés ;
//! - frontières de streaming React : `<template id="B:n">` est remplacé par le contenu de `<div hidden id="S:n">` ;
//! - gabarit appris par source : texte d'un bloc feuille présent dans une part des pages du site ;
//! - navigation : bloc fait de liens internes, sans prose ; titre qui est un lien vers une autre page du site ;
//! - racine du contenu : on descend vers l'enfant qui porte l'essentiel du texte hors liens, tant que ce qui est
//!   laissé de côté ne porte rien de technique (code, table, IOC).

use super::{Block, CtiEngine, Kind};
use ego_tree::{NodeId, NodeRef};
use scraper::{Html, Node};
use std::collections::{HashMap, HashSet};

type NRef<'a> = NodeRef<'a, Node>;

/// Éléments dont le texte n'est jamais du contenu.
const DROPPED: &[&str] = &[
    "script", "style", "noscript", "template", "svg", "canvas", "iframe", "object", "embed", "video", "audio", "form",
    "button", "input", "select", "textarea", "nav", "dialog", "head",
];
/// Éléments de bloc : ils ferment le paragraphe en cours.
const BLOCKS: &[&str] = &[
    "address", "article", "aside", "blockquote", "body", "center", "dd", "details", "div", "dl", "dt", "fieldset",
    "figcaption", "figure", "footer", "h1", "h2", "h3", "h4", "h5", "h6", "header", "hr", "html", "legend", "li", "main",
    "ol", "p", "pre", "section", "summary", "table", "tbody", "td", "tfoot", "th", "thead", "tr", "ul",
];
/// Éléments de texte du HTML. Tout autre nom (sans tiret : un tiret désigne un composant web) est un gabarit d'écriture
/// non échappé dans la source, `cmd /c <command>` ou `.[<victim_id>]` : on le rend tel qu'il est écrit.
const INLINE: &[&str] = &[
    "a", "abbr", "area", "b", "base", "bdi", "bdo", "big", "br", "caption", "cite", "code", "col", "colgroup", "data",
    "del", "dfn", "em", "font", "i", "img", "ins", "kbd", "label", "link", "map", "mark", "math", "menu", "meta", "meter",
    "nobr", "optgroup", "option", "output", "picture", "progress", "q", "rp", "rt", "ruby", "s", "samp", "search", "slot",
    "small", "source", "span", "strike", "strong", "sub", "sup", "time", "title", "tt", "track", "u", "var", "wbr",
    "hgroup", "marquee",
];
/// Une ancre d'au plus autant de mots qui porte un IOC est l'indicateur lui-même.
const IOC_ANCHOR_WORDS: usize = 4;
/// Part du texte hors liens qu'un enfant doit porter pour devenir la racine du contenu.
const ROOT_SHARE: usize = 85;
/// Un frère laissé de côté qui porte autant de mots hors liens est de la prose : on ne descend pas.
const ROOT_SIBLING_WORDS: usize = 12;

fn heading_level(tag: &str) -> Option<u8> {
    match tag {
        "h1" => Some(1),
        "h2" => Some(2),
        "h3" => Some(3),
        "h4" => Some(4),
        "h5" => Some(5),
        "h6" => Some(6),
        _ => None,
    }
}

fn is_block(tag: &str) -> bool {
    BLOCKS.contains(&tag)
}

/// `<victim_id>` tel qu'écrit dans la source, ou None pour un élément HTML.
fn literal_placeholder(el: &scraper::node::Element) -> Option<String> {
    let tag = el.name();
    if tag.contains('-') || INLINE.contains(&tag) || BLOCKS.contains(&tag) || DROPPED.contains(&tag) {
        return None;
    }
    let words: Vec<&str> = std::iter::once(tag).chain(el.attrs().filter(|(_, v)| v.is_empty()).map(|(k, _)| k)).collect();
    Some(format!("<{}>", words.join(" ")))
}

/// Texte d'un nœud texte, sans caractères invisibles.
fn clean_chars(s: &str) -> String {
    super::normalize_input(s)
}

fn collapse(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Forme canonique d'un bloc pour comparer le gabarit entre pages d'un même site.
fn norm_text(s: &str) -> String {
    let t: String = s.to_lowercase().chars().map(|c| if c.is_ascii_digit() { '0' } else { c }).collect();
    collapse(&t)
}

#[derive(Default, Clone, Copy, Debug)]
struct Stats {
    /// Caractères visibles (hors espaces).
    chars: usize,
    /// Dont texte de liens (un lien dont l'ancre est un IOC compte comme contenu).
    link_chars: usize,
    /// Mots hors liens.
    words: usize,
    links: usize,
    internal: usize,
    ioc_anchor: bool,
    /// Code, table de données ou IOC dans le sous-arbre.
    technical: bool,
    /// Le sous-arbre contient un élément de bloc.
    has_block: bool,
}

impl Stats {
    fn add(&mut self, o: &Stats) {
        self.chars += o.chars;
        self.link_chars += o.link_chars;
        self.words += o.words;
        self.links += o.links;
        self.internal += o.internal;
        self.ioc_anchor |= o.ioc_anchor;
        self.technical |= o.technical;
        self.has_block |= o.has_block;
    }

    fn content(&self) -> usize {
        self.chars - self.link_chars
    }
}

pub(crate) struct Page<'e> {
    engine: &'e CtiEngine,
    html: Html,
    /// Contenus différés du streaming React : `k` -> `<div hidden id="S:k">`.
    streams: HashMap<String, NodeId>,
    stats: HashMap<NodeId, Stats>,
    root_domain: Option<String>,
}

impl<'e> Page<'e> {
    pub(crate) fn parse(engine: &'e CtiEngine, src: &str, source_url: Option<&str>) -> Self {
        let html = Html::parse_document(src);
        let mut streams = HashMap::new();
        for n in html.tree.nodes() {
            if let Some(el) = n.value().as_element() {
                if el.name() == "div" && el.attr("hidden").is_some() {
                    if let Some(k) = el.id().and_then(|id| id.strip_prefix("S:")) {
                        streams.insert(k.to_string(), n.id());
                    }
                }
            }
        }
        let mut page = Page {
            engine,
            html,
            streams,
            stats: HashMap::new(),
            root_domain: source_url.and_then(super::extract_root_domain),
        };
        let body = page.body();
        let mut stats = HashMap::new();
        page.compute(body, &mut stats);
        page.stats = stats;
        page
    }

    fn body(&self) -> NodeId {
        let root = self.html.root_element();
        root.children()
            .find(|c| c.value().as_element().map_or(false, |e| e.name() == "body"))
            .map_or(root.id(), |c| c.id())
    }

    fn node(&self, id: NodeId) -> NRef<'_> {
        self.html.tree.get(id).expect("nœud du document")
    }

    fn dropped(el: &scraper::node::Element) -> bool {
        if DROPPED.contains(&el.name()) || el.attr("hidden").is_some() || el.attr("aria-hidden") == Some("true") {
            return true;
        }
        let style = Self::style(el);
        style.contains("display:none") || style.contains("visibility:hidden")
    }

    /// Style en ligne, minuscules et sans espaces.
    fn style(el: &scraper::node::Element) -> String {
        el.attr("style").unwrap_or("").chars().filter(|c| !c.is_whitespace()).collect::<String>().to_lowercase()
    }

    /// Enfants lus d'un nœud : éléments non écartés et textes, frontières de streaming résolues.
    fn children(&self, id: NodeId) -> Vec<NodeId> {
        let n = self.node(id);
        let mut out = Vec::new();
        let mut skipping = false;
        let mut cursor = n.first_child();
        while let Some(c) = cursor {
            cursor = c.next_sibling();
            if skipping {
                if let Node::Comment(cm) = c.value() {
                    skipping = cm.trim() != "/$";
                }
                continue;
            }
            match c.value() {
                Node::Element(el) => {
                    if el.name() == "template" {
                        let stream = el.id().and_then(|i| i.strip_prefix("B:")).and_then(|k| self.streams.get(k));
                        if let Some(&s) = stream {
                            out.extend(self.children(s));
                            // Le repli affiché avant le streaming court jusqu'au commentaire `/$` de la frontière.
                            skipping = Self::closes_boundary(c);
                            continue;
                        }
                    }
                    if !Self::dropped(el) {
                        out.push(c.id());
                    }
                }
                Node::Text(_) => out.push(c.id()),
                _ => {}
            }
        }
        out
    }

    fn closes_boundary(start: NRef<'_>) -> bool {
        let mut s = start.next_sibling();
        while let Some(n) = s {
            if let Node::Comment(cm) = n.value() {
                if cm.trim() == "/$" {
                    return true;
                }
            }
            s = n.next_sibling();
        }
        false
    }

    fn tag(&self, id: NodeId) -> Option<&str> {
        self.node(id).value().as_element().map(|e| e.name())
    }

    fn compute(&self, id: NodeId, out: &mut HashMap<NodeId, Stats>) -> Stats {
        let mut s = Stats::default();
        match self.node(id).value() {
            Node::Text(t) => {
                let t = clean_chars(t);
                s.chars = t.chars().filter(|c| !c.is_whitespace()).count();
                s.words = t.split_whitespace().filter(|w| w.chars().any(|c| c.is_alphanumeric())).count();
                s.technical = self.engine.re_ioc_hint.is_match(&t);
                return s;
            }
            Node::Element(el) => {
                for c in self.children(id) {
                    let cs = self.compute(c, out);
                    s.add(&cs);
                }
                let tag = el.name();
                if is_block(tag) {
                    s.has_block = true;
                }
                if tag == "pre" || (tag == "table" && self.is_data_table(id)) {
                    s.technical = true;
                }
                if tag == "a" && el.attr("href").is_some() && s.chars > 0 {
                    // L'ancre EST l'indicateur (CVE, condensat, adresse) : du contenu. Un titre d'article qui cite une CVE
                    // reste un lien de navigation.
                    if s.technical && s.words <= IOC_ANCHOR_WORDS {
                        s.ioc_anchor = true;
                    } else {
                        s.technical = false;
                        s.link_chars = s.chars;
                        s.words = 0;
                        s.links += 1;
                        let href = el.attr("href").unwrap_or("");
                        if !href.contains("://") || super::is_internal(href, self.root_domain.as_deref()) {
                            s.internal += 1;
                        }
                    }
                }
            }
            _ => {}
        }
        out.insert(id, s);
        s
    }

    fn stats(&self, id: NodeId) -> Stats {
        self.stats.get(&id).copied().unwrap_or_default()
    }

    /// Table de données : au moins deux lignes et deux colonnes, sans table imbriquée ni bloc de mise en page.
    fn is_data_table(&self, id: NodeId) -> bool {
        let rows = self.rows(id);
        if rows.len() < 2 || rows.iter().map(|r| r.len()).max().unwrap_or(0) < 2 {
            return false;
        }
        !self.node(id).descendants().skip(1).any(|d| {
            d.value().as_element().map_or(false, |e| matches!(e.name(), "table" | "pre" | "ul" | "ol" | "h1" | "h2" | "h3"))
        })
    }

    fn rows(&self, table: NodeId) -> Vec<Vec<NodeId>> {
        let mut rows = Vec::new();
        self.collect_rows(table, &mut rows);
        rows.into_iter()
            .map(|r| self.children(r).into_iter().filter(|c| matches!(self.tag(*c), Some("td" | "th"))).collect())
            .collect()
    }

    fn collect_rows(&self, id: NodeId, rows: &mut Vec<NodeId>) {
        for c in self.children(id) {
            match self.tag(c) {
                Some("tr") => rows.push(c),
                Some("thead" | "tbody" | "tfoot") => self.collect_rows(c, rows),
                _ => {}
            }
        }
    }

    /// Bloc de navigation : texte fait de liens, presque sans prose, liens surtout internes ; ou accroche tronquée
    /// (« … ») menant à une page du site. Un lien dont l'ancre est un IOC est du contenu.
    fn is_nav(&self, id: NodeId) -> bool {
        let s = self.stats(id);
        if s.links == 0 || s.ioc_anchor {
            return false;
        }
        let mostly_internal = s.internal * 10 >= s.links * 7;
        let dense = s.link_chars * 2 >= s.chars && s.words < 25 && mostly_internal;
        dense || (s.internal > 0 && s.words < 60 && {
            let t = self.inline_text(id);
            let t = t.trim_end();
            t.ends_with('…') || t.ends_with("...")
        })
    }

    /// Texte d'un sous-arbre sur une ligne.
    fn inline_text(&self, id: NodeId) -> String {
        let mut buf = String::new();
        self.raw_text(id, &mut buf);
        collapse(&buf)
    }

    /// Texte d'un sous-arbre, espaces conservés (`<br>` -> saut de ligne) : contenu d'un bloc de code.
    fn raw_text(&self, id: NodeId, buf: &mut String) {
        self.raw_text_in(id, buf, false);
    }

    /// Texte d'un bloc de code : sans ce que le lecteur ne peut pas copier (numéros de ligne en `user-select: none`).
    fn code_text(&self, id: NodeId) -> String {
        let mut buf = String::new();
        self.raw_text_in(id, &mut buf, true);
        buf
    }

    fn raw_text_in(&self, id: NodeId, buf: &mut String, code: bool) {
        match self.node(id).value() {
            Node::Text(t) => buf.push_str(&clean_chars(t)),
            Node::Element(el) => {
                if el.name() == "br" {
                    buf.push('\n');
                }
                if code && Self::style(el).contains("user-select:none") {
                    return;
                }
                if let Some(lit) = literal_placeholder(el) {
                    buf.push_str(&lit);
                }
                let block = is_block(el.name()) && el.name() != "pre";
                if block && !buf.ends_with('\n') && !buf.is_empty() {
                    buf.push('\n');
                }
                for c in self.children(id) {
                    self.raw_text_in(c, buf, code);
                }
                if block && !buf.ends_with('\n') {
                    buf.push('\n');
                }
            }
            _ => {}
        }
    }

    /// Racine du contenu : depuis `<body>`, on descend dans l'enfant qui porte au moins ROOT_SHARE % du texte hors liens,
    /// tant que ce qui est laissé de côté n'est ni de la prose (un article peut être réparti entre plusieurs conteneurs
    /// frères) ni technique.
    fn content_root(&self) -> NodeId {
        let mut cur = self.body();
        loop {
            let total = self.stats(cur).content();
            let kids = self.children(cur);
            let best = kids.iter().copied().filter(|k| self.tag(*k).is_some()).max_by_key(|k| self.stats(*k).content());
            let Some(best) = best else { return cur };
            let share_ok = self.stats(best).content() * 100 >= total * ROOT_SHARE;
            let rest_is_chrome = kids.iter().filter(|k| **k != best).all(|k| {
                let s = self.stats(*k);
                !s.technical && s.words < ROOT_SIBLING_WORDS
            });
            // La racine est un conteneur de blocs, jamais un paragraphe : son titre resterait de côté.
            let container = self.children(best).iter().any(|c| self.stats(*c).has_block);
            if total == 0 || !share_ok || !rest_is_chrome || !container {
                return cur;
            }
            cur = best;
        }
    }

    /// Texte visible de toute la page (hors scripts, éléments cachés et formulaires), un bloc par ligne.
    pub(crate) fn text(&self) -> String {
        let mut buf = String::new();
        self.raw_text(self.body(), &mut buf);
        buf.lines().map(collapse).filter(|l| !l.is_empty()).collect::<Vec<_>>().join("\n")
    }

    /// Clés de gabarit de la page : le texte normalisé de chaque bloc feuille (sans bloc imbriqué), hors titres, code et
    /// tables. Le texte seul, sans le chemin de balises : un même encart (appel à l'action, encadré « à propos ») est inséré
    /// à des profondeurs différentes d'une page à l'autre.
    pub(crate) fn template_keys(&self) -> Vec<String> {
        let mut keys = HashSet::new();
        self.collect_keys(self.body(), &mut keys);
        let mut out: Vec<String> = keys.into_iter().collect();
        out.sort();
        out
    }

    fn collect_keys(&self, id: NodeId, keys: &mut HashSet<String>) {
        for c in self.children(id) {
            let Some(tag) = self.tag(c) else { continue };
            if heading_level(tag).is_some() || matches!(tag, "pre" | "table" | "code") {
                continue;
            }
            match self.leaf_key(c) {
                Some(k) => {
                    keys.insert(k);
                }
                None => self.collect_keys(c, keys),
            }
        }
    }

    /// Clé d'un bloc feuille, ou None s'il contient d'autres blocs (on descend alors). Jamais de ligne de code ni de
    /// paragraphe tout en gras (un titre implicite : la structure de l'article, qui se répète d'un rapport à l'autre).
    fn leaf_key(&self, id: NodeId) -> Option<String> {
        let tag = self.tag(id)?;
        if !is_block(tag) || self.children(id).iter().any(|c| self.stats(*c).has_block) {
            return None;
        }
        let text = self.inline_text(id);
        if super::is_code_like(&text) || self.all_bold(id) {
            return None;
        }
        let norm = norm_text(&text);
        (4..=4000).contains(&norm.chars().count()).then_some(norm)
    }

    fn all_bold(&self, id: NodeId) -> bool {
        let (bold, total) = self.bold_chars(id, false);
        total > 0 && bold == total
    }

    fn bold_chars(&self, id: NodeId, in_bold: bool) -> (usize, usize) {
        match self.node(id).value() {
            Node::Text(t) => {
                let n = t.chars().filter(|c| !c.is_whitespace()).count();
                (if in_bold { n } else { 0 }, n)
            }
            Node::Element(el) => {
                let b = in_bold || matches!(el.name(), "strong" | "b");
                self.children(id).into_iter().fold((0, 0), |(x, y), c| {
                    let (bx, by) = self.bold_chars(c, b);
                    (x + bx, y + by)
                })
            }
            _ => (0, 0),
        }
    }

    /// Titre de carte : un titre entièrement couvert par un lien vers une autre page du site (articles liés, derniers
    /// articles). Un titre d'article ne mène nulle part, ou à sa propre ancre.
    fn is_card_title(&self, id: NodeId) -> bool {
        let internal_page = |href: &str| {
            !href.starts_with('#')
                && (!href.contains("://") || super::is_internal(href, self.root_domain.as_deref()))
        };
        let n = self.node(id);
        let up = n.ancestors().take(3).find_map(|a| a.value().as_element().filter(|e| e.name() == "a").map(|e| e.attr("href")));
        if let Some(href) = up {
            return href.map_or(false, internal_page);
        }
        let s = self.stats(id);
        s.links > 0 && s.link_chars == s.chars
            && n.descendants().filter_map(|d| d.value().as_element()).filter(|e| e.name() == "a").all(|e| e.attr("href").map_or(false, internal_page))
    }

    /// Blocs du contenu, dans l'ordre du document.
    pub(crate) fn blocks(&self, boilerplate: &HashSet<String>) -> Vec<Block> {
        let mut r = Renderer::new(self, boilerplate);
        for c in self.children(self.content_root()) {
            r.node(c);
        }
        r.finish()
    }
}

/// Parcours du contenu vers des blocs Markdown. Un paragraphe en cours (`cur`) est fermé par tout élément de bloc ; dans une
/// liste, il devient une ligne `- …` de la liste en cours.
struct Renderer<'p, 'e> {
    page: &'p Page<'e>,
    boilerplate: &'p HashSet<String>,
    blocks: Vec<Block>,
    cur: String,
    /// Caractères (hors espaces) du paragraphe en cours, et ceux qui sont en gras : un paragraphe tout en gras, court et
    /// sans ponctuation de phrase est un titre implicite.
    cur_chars: usize,
    cur_bold: usize,
    bold: usize,
    last_level: u8,
    /// Liste en cours : lignes rendues et pile (numérotée ?, numéro courant, l'élément a-t-il déjà sa ligne marquée ?).
    list_lines: Vec<String>,
    lists: Vec<(bool, usize, bool)>,
}

impl<'p, 'e> Renderer<'p, 'e> {
    fn new(page: &'p Page<'e>, boilerplate: &'p HashSet<String>) -> Self {
        Renderer {
            page,
            boilerplate,
            blocks: Vec::new(),
            cur: String::new(),
            cur_chars: 0,
            cur_bold: 0,
            bold: 0,
            last_level: 1,
            list_lines: Vec::new(),
            lists: Vec::new(),
        }
    }

    fn push(&mut self, kind: Kind, text: String) {
        self.flush_list();
        self.blocks.push(Block { kind, text });
    }

    /// Ferme le paragraphe en cours.
    fn flush(&mut self) {
        let text: String = self.cur.lines().map(collapse).filter(|l| !l.is_empty()).collect::<Vec<_>>().join("\n");
        let all_bold = self.cur_chars > 0 && self.cur_bold >= self.cur_chars;
        self.cur.clear();
        self.cur_chars = 0;
        self.cur_bold = 0;
        if !text.chars().any(|c| c.is_alphanumeric()) {
            return;
        }
        let depth = self.lists.len();
        if let Some((numbered, n, marked)) = self.lists.last_mut() {
            let indent = "  ".repeat(depth - 1);
            let line = collapse(&text);
            let line = if *marked {
                format!("{indent}  {line}")
            } else {
                *marked = true;
                if *numbered {
                    format!("{indent}{n}. {line}")
                } else {
                    format!("{indent}- {line}")
                }
            };
            self.list_lines.push(line);
            return;
        }
        if all_bold && !text.contains('\n') {
            let title = text.trim_matches(|c: char| c == '*' || c.is_whitespace()).trim_end_matches(':').trim();
            let words = title.split_whitespace().count();
            if title.chars().count() <= 90
                && words > 0
                && !super::ends_sentence(title)
                && !title.ends_with('?')
                && !self.page.engine.is_technical(title)
            {
                let level = (self.last_level + 1).min(6);
                self.blocks.push(Block { kind: Kind::Heading(level), text: title.to_string() });
                return;
            }
        }
        self.push(Kind::Text, text);
    }

    fn flush_list(&mut self) {
        if !self.list_lines.is_empty() {
            let text = std::mem::take(&mut self.list_lines).join("\n");
            self.blocks.push(Block { kind: Kind::Text, text });
        }
    }

    fn text(&mut self, t: &str) {
        let t = clean_chars(t);
        let n = t.chars().filter(|c| !c.is_whitespace()).count();
        self.cur_chars += n;
        if self.bold > 0 {
            self.cur_bold += n;
        }
        // Les espaces du HTML sont repliés ; une fin de ligne ne vient que de `<br>`.
        let mut prev_space = self.cur.ends_with([' ', '\n']) || self.cur.is_empty();
        for c in t.chars() {
            if c.is_whitespace() {
                if !prev_space {
                    self.cur.push(' ');
                    prev_space = true;
                }
            } else {
                self.cur.push(c);
                prev_space = false;
            }
        }
    }

    fn node(&mut self, id: NodeId) {
        let page = self.page;
        let n = page.node(id);
        let el = match n.value() {
            Node::Text(t) => return self.text(t),
            Node::Element(el) => el,
            _ => return,
        };
        let tag = el.name();

        if let Some(level) = heading_level(tag) {
            self.flush();
            if page.is_card_title(id) {
                return;
            }
            let title = page.inline_text(id);
            let title = title.trim().trim_end_matches(':').trim().to_string();
            if title.chars().any(|c| c.is_alphanumeric()) {
                self.last_level = level;
                self.push(Kind::Heading(level), title);
            }
            return;
        }
        match tag {
            "br" => {
                if self.lists.is_empty() {
                    self.cur.push('\n');
                } else {
                    self.text(" ");
                }
                return;
            }
            "img" | "hr" | "wbr" => {
                if tag == "hr" {
                    self.flush();
                }
                return;
            }
            "pre" => {
                self.flush();
                self.code(id);
                return;
            }
            "code" if self.cur.trim().is_empty() && page.code_text(id).trim().contains('\n') => {
                // `<code>` affiché en bloc, sans `<pre>`
                self.flush();
                self.code(id);
                return;
            }
            "table" if page.is_data_table(id) => {
                self.flush();
                self.table(id);
                return;
            }
            _ => {}
        }

        if is_block(tag) && tag != "li" {
            if page.leaf_key(id).map_or(false, |k| self.boilerplate.contains(&k)) {
                return;
            }
            if page.is_nav(id) {
                return;
            }
        }

        match tag {
            "ul" | "ol" => {
                self.flush();
                self.lists.push((tag == "ol", 0, false));
                for c in page.children(id) {
                    self.node(c);
                }
                self.flush();
                self.lists.pop();
                if self.lists.is_empty() {
                    self.flush_list();
                }
            }
            "li" => {
                self.flush();
                if page.leaf_key(id).map_or(false, |k| self.boilerplate.contains(&k)) || page.is_nav(id) {
                    return;
                }
                // `<li>` hors de toute liste : une liste à lui seul
                let orphan = self.lists.is_empty();
                if orphan {
                    self.lists.push((false, 0, false));
                }
                if let Some(top) = self.lists.last_mut() {
                    top.1 += 1;
                    top.2 = false;
                }
                for c in page.children(id) {
                    self.node(c);
                }
                self.flush();
                if orphan {
                    self.lists.pop();
                    self.flush_list();
                }
            }
            "a" => {
                let href = el.attr("href").unwrap_or("").trim().to_string();
                for c in page.children(id) {
                    self.node(c);
                }
                // Lien externe vers un échantillon : l'URL porte un condensat que l'ancre ne montre pas (souvent un autre
                // hachage du même fichier), on la garde.
                let anchor = page.inline_text(id).to_lowercase();
                let external = href.contains("://") && !super::is_internal(&href, page.root_domain.as_deref());
                let hidden_hash = page.engine.re_hex_hash.find_iter(&href).any(|m| !anchor.contains(&m.as_str().to_lowercase()));
                if external && hidden_hash {
                    self.text(&format!(" ({href})"));
                }
            }
            "code" | "kbd" | "samp" | "tt" => {
                let t = page.inline_text(id);
                if t.is_empty() {
                    return;
                }
                self.text(&format!("`{}`", t.replace('`', "'")));
            }
            "strong" | "b" => {
                self.bold += 1;
                for c in page.children(id) {
                    self.node(c);
                }
                self.bold -= 1;
            }
            _ => {
                if let Some(lit) = literal_placeholder(el) {
                    self.text(&lit);
                }
                let block = is_block(tag);
                if block {
                    self.flush();
                }
                for c in page.children(id) {
                    self.node(c);
                }
                if block {
                    self.flush();
                }
            }
        }
    }

    fn code(&mut self, id: NodeId) {
        let raw = self.page.code_text(id);
        let lines: Vec<&str> = raw.lines().map(|l| l.trim_end()).collect();
        let start = lines.iter().position(|l| !l.trim().is_empty());
        let end = lines.iter().rposition(|l| !l.trim().is_empty());
        let (Some(s), Some(e)) = (start, end) else { return };
        let body = lines[s..=e].join("\n");
        let fence = if body.contains("```") { "~~~" } else { "```" };
        self.push(Kind::Code, format!("{fence}\n{}\n{fence}", self.page.engine.refang_code(&body)));
    }

    fn table(&mut self, id: NodeId) {
        let rows = self.page.rows(id);
        let width = rows.iter().map(|r| r.len()).max().unwrap_or(0);
        let mut lines = Vec::with_capacity(rows.len() + 1);
        for (i, r) in rows.iter().enumerate() {
            let mut cells: Vec<String> =
                r.iter().map(|c| self.page.inline_text(*c).replace('|', "\\|")).collect();
            cells.resize(width, String::new());
            lines.push(format!("| {} |", cells.join(" | ")));
            if i == 0 {
                lines.push(format!("|{}", " --- |".repeat(width)));
            }
        }
        self.push(Kind::Table, lines.join("\n"));
    }

    fn finish(mut self) -> Vec<Block> {
        self.flush();
        self.lists.clear();
        self.flush_list();
        self.blocks
    }
}
