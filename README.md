# TSym
Text based symbol format for Ghidra and (soon) IDA

## Roadmap
 - [X] Import headers instead of inlining the entire path (will take a while)
   - Requires import path to be set to the types folder.
 - [ ] Detect classes and add methods (both normal and virtual) to the headers
 - [ ] Local names
 - [X] Support my `inherit` field name (used in place of extending so Ghidra will enjoy it)
   - For multiple inheritance under the same struct, you can put the comment as "inherit"