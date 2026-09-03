# Conformance vectors

Each vector pins an **external** fixture by commit and sha256. Nothing here is
copied from another project's repository — a vector records where the bytes
live and what they must hash to, so a drifting upstream is a test failure rather
than a silent divergence.

A vector states what it does NOT cover. A test that cannot say "I did not check
this" turns absence into a pass.
