use regex::Regex;

fn find_xss_vulnerabilities(input: &str) -> Vec<String> {
    let pattern = Regex::new(r"(?i)<script.*?>.*?</script>").unwrap();
    let mut vulnerabilities = Vec::new();

    for capture in pattern.captures_iter(input) {
        if let Some(matched) = capture.get(0) {
            vulnerabilities.push(matched.as_str().to_string());
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
