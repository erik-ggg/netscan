//! Tiny text helpers shared by SSDP and the deep-scan probes.

const MAX_LEN: usize = 120;

/// Collapse whitespace, strip control characters and cap the length.
pub fn clean(s: &str) -> String {
    let t: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let t = t.split_whitespace().collect::<Vec<_>>().join(" ");
    if t.chars().count() > MAX_LEN {
        t.chars().take(MAX_LEN).collect()
    } else {
        t
    }
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// Text of the first `<tag>`…`</tag>` (namespace prefixes and attributes tolerated).
pub fn xml_tag(xml: &str, tag: &str) -> Option<String> {
    let lower = xml.to_ascii_lowercase();
    let open = format!("<{}", tag.to_ascii_lowercase());
    let close = format!("</{}>", tag.to_ascii_lowercase());
    let mut from = 0;
    while let Some(i) = lower[from..].find(&open) {
        let start = from + i + open.len();
        from = start;
        // Must be the whole tag name, not a prefix of a longer one.
        match lower.as_bytes().get(start) {
            Some(b'>') | Some(b' ') | Some(b'/') => {}
            _ => continue,
        }
        let gt = lower[start..].find('>')? + start;
        if lower.as_bytes()[gt - 1] == b'/' {
            return None;
        }
        let end = lower[gt..].find(&close)? + gt;
        let v = clean(&unescape(&xml[gt + 1..end]));
        return (!v.is_empty()).then_some(v);
    }
    None
}

/// Contents of the first `<title>` of an HTML page (used by the deep-scan probes).
pub fn html_title(html: &str) -> Option<String> {
    xml_tag(html, "title")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_tag_basic_and_entities() {
        let x = "<root><friendlyName>Tom &amp; Jerry&apos;s TV</friendlyName><modelName>X</modelName></root>";
        assert_eq!(
            xml_tag(x, "friendlyName").as_deref(),
            Some("Tom & Jerry's TV")
        );
        assert_eq!(xml_tag(x, "modelName").as_deref(), Some("X"));
        assert_eq!(xml_tag(x, "missing"), None);
    }

    #[test]
    fn xml_tag_not_prefix_and_attrs() {
        let x = "<modelNameExtra>no</modelNameExtra><modelName lang=\"en\">yes</modelName>";
        assert_eq!(xml_tag(x, "modelName").as_deref(), Some("yes"));
    }

    #[test]
    fn caps_length_and_title() {
        let long = format!("<a>{}</a>", "x".repeat(500));
        assert_eq!(xml_tag(&long, "a").unwrap().len(), 120);
        assert_eq!(
            html_title("<HTML><TITLE>\n webOS  TV </TITLE>").as_deref(),
            Some("webOS TV")
        );
    }
}
