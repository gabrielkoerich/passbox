//! Renders secret names as a tree, the way `pass` does, for people rather than for pipes.

use std::collections::BTreeMap;
use std::fmt::Write;

#[derive(Default)]
struct Node {
    children: BTreeMap<String, Node>,
}

impl Node {
    fn insert(&mut self, path: &str) {
        let mut at = self;
        for part in path.split('/').filter(|p| !p.is_empty()) {
            at = at.children.entry(part.to_string()).or_default();
        }
    }

    fn render(&self, prefix: &str, out: &mut String) {
        let last_index = self.children.len().saturating_sub(1);
        for (i, (name, child)) in self.children.iter().enumerate() {
            let last = i == last_index;
            let branch = if last { "└── " } else { "├── " };

            // A node with children is a namespace, which is the thing worth picking out
            let label = if child.children.is_empty() {
                name.clone()
            } else {
                format!("\x1b[1;34m{name}\x1b[0m")
            };
            let _ = writeln!(out, "{prefix}{branch}{label}");

            let deeper = format!("{prefix}{}", if last { "    " } else { "│   " });
            child.render(&deeper, out);
        }
    }
}

/// Namespaces are coloured, since only a terminal is shown the tree
pub(crate) fn render(names: &[String]) -> String {
    let mut root = Node::default();
    for name in names {
        root.insert(name);
    }
    let mut out = String::from("passbox\n");
    root.render("", &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().copied().map(String::from).collect()
    }

    fn plain(out: &str) -> String {
        out.replace("\x1b[1;34m", "").replace("\x1b[0m", "")
    }

    #[test]
    fn nests_by_namespace() {
        let out = plain(&render(&names(&[
            "acme/api-key",
            "acme/signing-key",
            "top",
        ])));
        assert_eq!(
            out,
            "passbox\n\
             ├── acme\n\
             │   ├── api-key\n\
             │   └── signing-key\n\
             └── top\n"
        );
    }

    #[test]
    fn deep_paths_keep_indenting() {
        let out = plain(&render(&names(&[
            "r2/storage/access-key-id",
            "r2/storage/secret",
        ])));
        assert_eq!(
            out,
            "passbox\n\
             └── r2\n\
             \x20   └── storage\n\
             \x20       ├── access-key-id\n\
             \x20       └── secret\n"
        );
    }

    /// Colour marks namespaces, so a leaf never carries an escape sequence
    #[test]
    fn colour_only_marks_namespaces() {
        let out = render(&names(&["acme/api-key", "top"]));
        assert!(out.contains("\x1b[1;34macme\x1b[0m"));
        assert!(out.contains("└── top\n"));
        assert!(!out.contains("\x1b[1;34mtop"));
        assert!(!out.contains("\x1b[1;34mapi-key"));
    }

    #[test]
    fn an_empty_store_renders_just_the_root() {
        assert_eq!(render(&[]), "passbox\n");
    }
}
