


use html5ever::tendril::TendrilSink;
use html5ever::{parse_document, serialize};
use kuchiki::traits::TendrilSinkExt;
use std::borrow::Cow;
use url::Url;

fn find_xss_vulnerabilities(input: &str) -> Vec<String> {
    let mut vulnerabilities = Vec::new();
    let input_sink = kuchiki::TendrilSink::new();
    let dom = parse_document(kuchiki::parse_html().from_utf8().read_from(&mut input.as_bytes()))
        .expect("Failed to parse HTML");
    for script_node in dom.select("script").expect("Failed to select script nodes") {
        if let Some(src_attr) = script_node.attributes.borrow().get("src") {
            if let Ok(url) = Url::parse(src_attr) {
                if url.scheme() == "javascript" {
                    vulnerabilities.push(serialize(&script_node).to_string());
                }
            }
        } else {
            vulnerabilities.push(serialize(&script_node).to_string());
        }
    }
    vulnerabilities
}
fn main() {
    let input = r#"
        <h1>Hello, World!</h1>
        <script>alert("XSS");</script>
        <p>Some text.</p>
        <script src="http://example.com/malicious.js"></script>
    "#;

    let vulnerabilities = find_xss_vulnerabilities(input);

    for vulnerability in vulnerabilities {
        println!("XSS vulnerability found: {}", vulnerability);
    }
}


