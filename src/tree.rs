//! Renders secret names as a tree, the way `pass` does, for people rather than for pipes.

use std::collections::BTreeMap;

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

    fn render(&self, prefix: &str, colour: bool, out: &mut String) {
        let last_index = self.children.len().saturating_sub(1);
        for (i, (name, child)) in self.children.iter().enumerate() {
            let last = i == last_index;
            let branch = if last { "└── " } else { "├── " };

            // A node with children is a namespace, which is the thing worth picking out
            let label = if colour && !child.children.is_empty() {
                format!("\x1b[1;34m{name}\x1b[0m")
            } else {
                name.clone()
            };
            out.push_str(&format!("{prefix}{branch}{label}\n"));

            let deeper = format!("{prefix}{}", if last { "    " } else { "│   " });
            child.render(&deeper, colour, out);
        }
    }
}

pub fn render(names: &[String], colour: bool) -> String {
    let mut root = Node::default();
    for name in names {
        root.insert(name);
    }
    let mut out = String::from("passbox\n");
    root.render("", colour, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn nests_by_namespace() {
        let out = render(
            &names(&["bean/api-key", "bean/hl-mainnet-pk", "top"]),
            false,
        );
        assert_eq!(
            out,
            "passbox\n\
             ├── bean\n\
             │   ├── api-key\n\
             │   └── hl-mainnet-pk\n\
             └── top\n"
        );
    }

    #[test]
    fn deep_paths_keep_indenting() {
        let out = render(
            &names(&["r2/storage/access-key-id", "r2/storage/secret"]),
            false,
        );
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
        let out = render(&names(&["bean/api-key", "top"]), true);
        assert!(out.contains("\x1b[1;34mbean\x1b[0m"));
        assert!(out.contains("└── top\n"));
        assert!(!out.contains("\x1b[1;34mtop"));
        assert!(!out.contains("\x1b[1;34mapi-key"));
    }

    #[test]
    fn an_empty_store_renders_just_the_root() {
        assert_eq!(render(&[], false), "passbox\n");
    }
}
