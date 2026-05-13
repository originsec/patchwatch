use pulldown_cmark::{html, Options, Parser};

pub fn render_markdown(md: &str) -> String {
    let opts = Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH;
    let parser = Parser::new_ext(md, opts);
    let mut out = String::with_capacity(md.len() * 2);
    html::push_html(&mut out, parser);
    out
}
