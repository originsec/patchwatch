use std::sync::LazyLock;
use syntect::{highlighting::ThemeSet, html::highlighted_html_for_string, parsing::SyntaxSet};

static SS: LazyLock<SyntaxSet> = LazyLock::new(SyntaxSet::load_defaults_newlines);
static TS: LazyLock<ThemeSet> = LazyLock::new(ThemeSet::load_defaults);

pub fn highlight_c(code: &str) -> String {
    let syntax = SS.find_syntax_by_extension("c").unwrap_or_else(|| SS.find_syntax_plain_text());
    let theme = &TS.themes["InspiredGitHub"];
    highlighted_html_for_string(code, &SS, syntax, theme)
        .unwrap_or_else(|_| html_escape_fallback(code))
}

fn html_escape_fallback(s: &str) -> String {
    format!(
        "<pre>{}</pre>",
        s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn highlights_c_snippet() {
        let out = highlight_c("int main(void) { return 0; }");
        assert!(out.contains('<'), "expected HTML in output");
    }
}
