# Style Guide for Submissions to this repository
> Disclaimer: While this document covers the style guide for contributing to this repository, actually submitting contributions are restricted to DeTraced researchers. You can find out more information in the [CONTRIBUTING.md](CONTRIBUTING.md) file.

## YARA Rules
When creating Yara rules make sure to follow the following template for each ruleset and rule.

```c
/*
   YARA Rule Set
   Author: DeTraced Security
   Date: yyyy-dd-mm
   Identifier: Malware Identifier
   Reference: Link to DeTraced b1log post
*/

/* Rule Set ----------------------------------------------------------------- */

rule name {
   meta:
      description = "Description of rule"
      author = "DeTraced Security"
      reference = "Link to DeTraced blog post"
      date = "yyyy-dd-mm"
      hash1 = "file hash"
   strings:
      Strings go here
   condition:
      Conditions go here
}
```

Each malware family for a specific threat actor should be in its own ruleset, but individual samples from the same family should be in the same ruleset.

## IOCs

Work In Progress

## Repository Structure
```
/
├── groups/
│   ├── group-1/
│   │   ├── iocs.txt
│   │   └── yara/
│   │       └── group-1_loader.yar
│   │
│   └── group-2/
│       ├── iocs.txt
│       └── report.md
│   
├── malware/
│   ├── ransomware_family/
│   │   ├── iocs.txt
│   │   ├── yara/
│   │   │   └── ransomware_family.yar
│   │   └── report.md
│   └── stealer_family/
│       ├── iocs.txt
│       ├── yara/
│       └── report.md
│docs/
│   ├── CONTRIBUTING.md
│   ├── STYLE-GUIDE.md
│   └── DISCLAIMER.md
│
└── README.md
```