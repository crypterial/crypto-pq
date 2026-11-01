// The examples of the repository's README.md are not in the published crate, so they cannot run as
// doc tests there. Each one must equal an example of the crate's README.md, which does.

const REPOSITORY: &str = include_str!("../../README.md");

const CRATE: &str = include_str!("../README.md");

fn rust_blocks(markdown: &str) -> Vec<String> {
    let mut blocks = Vec::new();

    let mut current: Option<String> = None;

    for line in markdown.lines() {
        match current.as_mut() {
            None if line == "```rust" => current = Some(String::new()),
            None => {}
            Some(_) if line == "```" => blocks.extend(current.take()),
            Some(block) => {
                block.push_str(line);

                block.push('\n');
            }
        }
    }

    assert!(current.is_none(), "unterminated code block");

    blocks
}

#[test]
fn repository_examples_run_as_crate_doc_tests() {
    let tested = rust_blocks(CRATE);

    let shown = rust_blocks(REPOSITORY);

    assert!(!shown.is_empty());

    for block in &shown {
        assert!(
            tested.contains(block),
            "an example of README.md is not in rust/README.md:\n{block}"
        );
    }
}
