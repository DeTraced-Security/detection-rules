# detection-rules

Inside this repository you will find a collection of detection rules, indicators of compromise (IOCs), and other useful pieces of information from our various engagements.

This repository stands to help share actionable threat intelligence on the threat actors and malware we encounter.

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

## Contributing
This repository is open for anyone to use, but contributions are restricted to DeTraced Security researchers only. Further info can be found [here](/docs/CONTRIBUTING.md).

## Disclaimer

Check out our [disclaimer](/docs/DISCLAIMER.md).

---

Unless otherwise noted, all content is © DeTraced Security.
Rules and IOCs may be used, but redistribution or modification requires attribution.