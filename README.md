# TSym
Text based symbol format for Ghidra and (soon) IDA

## Roadmap
 - [X] Import headers instead of inlining the entire path (will take a while)
   - Requires import path to be set to the types folder.
 - [ ] Detect classes and add methods (both normal and virtual) to the headers
 - [ ] Local vars
 - [ ] Templates
 - [ ] Visibility via comments (e.g TS_PUBLIC, TS_PRIVATE, TS_PROTECTED in the comment)
 - [X] Support my `inherit` field name (used in place of extending so Ghidra will enjoy it)
   - For multiple inheritance under the same struct, you can put the comment as "inherit", or include "TS_INHERIT" in an existing comment.