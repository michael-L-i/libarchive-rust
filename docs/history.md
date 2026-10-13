# Published history

Before the first public push, generated Cargo build files were removed from
`vendor/lzma-rust2/target/` and `vendor/miniz_oxide/target/` in the unpublished
history. These files contained local build paths and were not source code.
The source tree, upstream pin, commit authors and dates were preserved.

Older benchmark reports and development notes use the original revisions.
[The revision map](history/commit-map.txt) translates those hashes to the
published history. An all-zero new hash denotes an artifact-only commit
removed during cleanup. The complete original history and experimental
branches are retained in a private local Git bundle outside this repository.
