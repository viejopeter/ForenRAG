# Third-Party Notices and Publication Provenance

The Apache License 2.0 in `LICENSE` applies only to original ForenRAG source code and project-authored documentation. It does not replace the licenses or terms that apply to third-party material in `knowledge_base/`.

Provenance was verified against public upstream repositories on 24 August 2026. Public availability on GitHub is not itself a license; the terms identified below govern redistribution and modification.

## Reproducibility Source Manifest

This document is the publication provenance record for every resource in [`knowledge_base/`](knowledge_base/). Commit-pinned URLs identify the version inspected; SHA-256 values identify the corresponding local file. The listed Atomic Red Team and LOLBAS files are byte-for-byte copies, renamed only.

## MITRE ATT&CK and Atomic Red Team Files

The following files are renamed, byte-for-byte copies of generated Atomic Red Team Markdown. They contain both Atomic Red Team test documentation and MITRE ATT&CK technique descriptions:

- `knowledge_base/atomic_t1003_001.md`
- `knowledge_base/atomic_t1003_002.md`
- `knowledge_base/atomic_t1053_005.md`
- `knowledge_base/atomic_t1059_001.md`
- `knowledge_base/atomic_t1105.md`
- `knowledge_base/atomic_t1543_003.md`
- `knowledge_base/atomic_t1547_001.md`
- `knowledge_base/atomic_t1548_002.md`

No content changes were found. The only local transformation was renaming and placement under `knowledge_base/`.

### Atomic Red Team Provenance

Seven files match the generated documentation in [redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team) at commit [`9f6a1eab36d561272cf9f34c61dd80263db3ce8e`](https://github.com/redcanaryco/atomic-red-team/commit/9f6a1eab36d561272cf9f34c61dd80263db3ce8e), dated 18 February 2026:

| Local file | Upstream path | Commit-pinned source | SHA-256 |
|---|---|---|---|
| `knowledge_base/atomic_t1003_002.md` | `atomics/T1003.002/T1003.002.md` | [View source](https://github.com/redcanaryco/atomic-red-team/blob/9f6a1eab36d561272cf9f34c61dd80263db3ce8e/atomics/T1003.002/T1003.002.md) | `ff7d395d942c7b9efe6cd048ef5e9571727046ade81246d3e24c808e2e7ca4bb` |
| `knowledge_base/atomic_t1053_005.md` | `atomics/T1053.005/T1053.005.md` | [View source](https://github.com/redcanaryco/atomic-red-team/blob/9f6a1eab36d561272cf9f34c61dd80263db3ce8e/atomics/T1053.005/T1053.005.md) | `45ff7daeec949f25cba956005bc300ff0d164550580609231cb56b80b7ec9c0e` |
| `knowledge_base/atomic_t1059_001.md` | `atomics/T1059.001/T1059.001.md` | [View source](https://github.com/redcanaryco/atomic-red-team/blob/9f6a1eab36d561272cf9f34c61dd80263db3ce8e/atomics/T1059.001/T1059.001.md) | `e8ae3f5e30a155ac725c6f1305583bdef295b0cdac80dfe5cbcf7bad673f6b2e` |
| `knowledge_base/atomic_t1105.md` | `atomics/T1105/T1105.md` | [View source](https://github.com/redcanaryco/atomic-red-team/blob/9f6a1eab36d561272cf9f34c61dd80263db3ce8e/atomics/T1105/T1105.md) | `8c4abc3fe39010125921855ac11fdab0429953bd290280de0e2615fa6289674f` |
| `knowledge_base/atomic_t1543_003.md` | `atomics/T1543.003/T1543.003.md` | [View source](https://github.com/redcanaryco/atomic-red-team/blob/9f6a1eab36d561272cf9f34c61dd80263db3ce8e/atomics/T1543.003/T1543.003.md) | `2d68b14e8e49cf5640756682cd4fdc97c067d8131016008104a2fb99c7dbacf6` |
| `knowledge_base/atomic_t1547_001.md` | `atomics/T1547.001/T1547.001.md` | [View source](https://github.com/redcanaryco/atomic-red-team/blob/9f6a1eab36d561272cf9f34c61dd80263db3ce8e/atomics/T1547.001/T1547.001.md) | `85ad5fa3b03e7ec8247d07b4421743a44a443206a68ef6e619b4214743b75585` |
| `knowledge_base/atomic_t1548_002.md` | `atomics/T1548.002/T1548.002.md` | [View source](https://github.com/redcanaryco/atomic-red-team/blob/9f6a1eab36d561272cf9f34c61dd80263db3ce8e/atomics/T1548.002/T1548.002.md) | `714879ea1bc69103d30346896552da490f7d26c5630a2f6b5e44c702063f9faf` |

`knowledge_base/atomic_t1003_001.md` matches `atomics/T1003.001/T1003.001.md` at commit [`f67d2c99bef718b0be44b16fe89b47d7acdbe7bc`](https://github.com/redcanaryco/atomic-red-team/commit/f67d2c99bef718b0be44b16fe89b47d7acdbe7bc), dated 23 June 2026.

| Local file | Upstream path | Commit-pinned source | SHA-256 |
|---|---|---|---|
| `knowledge_base/atomic_t1003_001.md` | `atomics/T1003.001/T1003.001.md` | [View source](https://github.com/redcanaryco/atomic-red-team/blob/f67d2c99bef718b0be44b16fe89b47d7acdbe7bc/atomics/T1003.001/T1003.001.md) | `d8c9ffed74f2e57c6c1514c6d1be07b436aa90ed4afe13c8d77c0651e88e032f` |

### Atomic Red Team License

Atomic Red Team is distributed under the MIT License:

```text
The MIT License

Copyright (c) 2018 Red Canary, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

### MITRE ATT&CK Terms

The technique descriptions remain subject to the [MITRE ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).

> The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free license to use ATT&CK® for research, development, and commercial purposes. Any copy you make for such purposes is authorized provided that you reproduce MITRE's copyright designation and this license in any such copy.

> © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.

MITRE provides ATT&CK information on an "AS IS" basis and disclaims express or implied warranties, including non-infringement, merchantability, and fitness for a particular purpose. ATT&CK® is a registered trademark of The MITRE Corporation. Its name is used solely to identify the source and does not imply endorsement of ForenRAG.

### Material Referenced by Atomic Tests

The Atomic documentation contains commands, examples, attributions, and hyperlinks involving additional projects and publications. A hyperlink or download command is not a license grant. Except for text reproduced in the knowledge files, remotely referenced tools, binaries, scripts, articles, and payloads are not distributed by ForenRAG and remain subject to their own terms.

`knowledge_base/atomic_t1548_002.md` contains an upstream test identified as adapted from MITRE ATT&CK Evaluations `attack-arsenal` material at commit `66650cebd33b9a1e180f7b31261da1789cdceb66`, which is distributed under Apache License 2.0. Its upstream adaptation attribution remains intact.

## LOLBAS Files

The following files are renamed, byte-for-byte copies from [LOLBAS-Project/LOLBAS](https://github.com/LOLBAS-Project/LOLBAS). No local content modifications were found.

| Local file | Upstream path | First-introduced blob commit | Compatible snapshot source | SHA-256 |
|---|---|---|---|---|
| `knowledge_base/lolbas_bitsadmin.yml` | `yml/OSBinaries/Bitsadmin.yml` | `dcca4db04a791de737a0cb455d0bb5fb381bea95` | [View source](https://github.com/LOLBAS-Project/LOLBAS/blob/a2784c79091cb282fefb68f0056a853cfafd7e3c/yml/OSBinaries/Bitsadmin.yml) | `1e282f4f1424fbc1a5cceb95ab057e643d95604a6f9cf14129cd1d117c5cc54d` |
| `knowledge_base/lolbas_certutil.yml` | `yml/OSBinaries/Certutil.yml` | `dcca4db04a791de737a0cb455d0bb5fb381bea95` | [View source](https://github.com/LOLBAS-Project/LOLBAS/blob/a2784c79091cb282fefb68f0056a853cfafd7e3c/yml/OSBinaries/Certutil.yml) | `9e10c346f9f2669ac96f4b1effd6f1701bdd989fde73fcc7fef2f43e9e9de3c4` |
| `knowledge_base/lolbas_reg.yml` | `yml/OSBinaries/Reg.yml` | `a79893e7ad7fe69e9eeb37c82e90685e10663312` | [View source](https://github.com/LOLBAS-Project/LOLBAS/blob/a2784c79091cb282fefb68f0056a853cfafd7e3c/yml/OSBinaries/Reg.yml) | `c70b8d36a9398e0902da99c7f0cac66d42413c80d5956bb022077280444f2fc5` |
| `knowledge_base/lolbas_rundll32.yml` | `yml/OSBinaries/Rundll32.yml` | `a79893e7ad7fe69e9eeb37c82e90685e10663312` | [View source](https://github.com/LOLBAS-Project/LOLBAS/blob/a2784c79091cb282fefb68f0056a853cfafd7e3c/yml/OSBinaries/Rundll32.yml) | `267b9ac4bd25820a87ac36b4a91e8c0ee4e13b04bc2e5f783c4396b240a90aa7` |
| `knowledge_base/lolbas_sc.yml` | `yml/OSBinaries/Sc.yml` | `a79893e7ad7fe69e9eeb37c82e90685e10663312` | [View source](https://github.com/LOLBAS-Project/LOLBAS/blob/a2784c79091cb282fefb68f0056a853cfafd7e3c/yml/OSBinaries/Sc.yml) | `2696d1c7463433d88ed8f3673007824f131ca6a44ccda5c2286889fe3ddbdb2b` |
| `knowledge_base/lolbas_schtasks.yml` | `yml/OSBinaries/Schtasks.yml` | `a79893e7ad7fe69e9eeb37c82e90685e10663312` | [View source](https://github.com/LOLBAS-Project/LOLBAS/blob/a2784c79091cb282fefb68f0056a853cfafd7e3c/yml/OSBinaries/Schtasks.yml) | `7fe2f1a2ecbadc9eed62347e5c2d410b2b1dceafd2f818e3ce06b10c0501f775` |

The exact checkout used during acquisition was not recorded. Compatible repository snapshots are `a2784c79091cb282fefb68f0056a853cfafd7e3c` from 29 June 2026 and `70f3ec38a565203d0ee44e8b7b28bf18422bf6ee` from 28 July 2026; both contain the exact six file blobs.

### LOLBAS License

- SPDX identifier: `GPL-3.0-only`
- License: [local GNU General Public License version 3](LICENSES/GPL-3.0-only.txt); [upstream LICENSE](https://github.com/LOLBAS-Project/LOLBAS/blob/master/LICENSE)
- Upstream notice: [local LOLBAS NOTICE.md](LICENSES/LOLBAS-NOTICE.md); [upstream NOTICE.md](https://github.com/LOLBAS-Project/LOLBAS/blob/master/NOTICE.md)

The six LOLBAS-derived YAML files remain under GPL-3.0-only. The Apache License for original ForenRAG code does not relicense them. Redistribution and modification must comply with GPL-3.0, preserve the project notice and existing author, acknowledgement, resource, detection, and ATT&CK fields, and identify any future modifications.

## CISA and NIST Incident-Response References

`knowledge_base/cisa_dfir_containment_playbook.md` is an independently prepared project document. It is not an official publication of CISA, the Department of Homeland Security, or NIST, and those agencies have not reviewed, approved, or endorsed it.

- Local file: `knowledge_base/cisa_dfir_containment_playbook.md`
- SHA-256: `707901d5d7d6edd56afd2e8b9da6bbdb3d1d3d8cf06801c144c714b385ef5f50`

The document was informed at a general level by:

- Cybersecurity and Infrastructure Security Agency, *Federal Government Cybersecurity Incident and Vulnerability Response Playbooks: Operational Procedures for Planning and Conducting Cybersecurity Incident and Vulnerability Response Activities in FCEB Information Systems* (November 2021), particularly the Cybersecurity Incident Response Playbook: [official landing page](https://www.cisa.gov/resources-tools/resources/federal-government-cybersecurity-incident-and-vulnerability-response-playbooks).
- Cichonski, P., Millar, T., Grance, T., and Scarfone, K. (2012), *Computer Security Incident Handling Guide*, NIST Special Publication 800-61 Revision 2: [DOI 10.6028/NIST.SP.800-61r2](https://doi.org/10.6028/NIST.SP.800-61r2).

NIST SP 800-61 Revision 2 was withdrawn on 3 April 2025 and superseded by [NIST SP 800-61 Revision 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final). Revision 2 is identified here as the historical source used by the project, not as current guidance.

The local document is not a reproduction of either publication. It condenses and reorganizes general incident-response concepts around selected ATT&CK techniques and adds project-authored Windows commands, event identifiers, product references, registry paths, and operational recommendations. These additions and omissions have not been validated by CISA or NIST.

Works authored by employees of the United States Government are generally not protected by copyright in the United States under 17 U.S.C. § 105. This does not necessarily apply to contractor-authored or other third-party material, and foreign copyright, trademark, seal, logo, publicity, and other rights may apply. NIST terms are available at [NIST Copyright, Fair Use, and Licensing Statements](https://www.nist.gov/open/license). Agency names identify historical sources and do not imply endorsement. No CISA or NIST name, logo, seal, or mark is licensed for use as project branding.

## External References

The knowledge files link to additional projects, articles, detection rules, tools, and payloads. A hyperlink is a reference, not a grant of rights. Content retrieved from those links remains subject to its own license and terms and is not bundled unless it appears directly in this repository.
