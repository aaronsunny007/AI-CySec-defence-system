# Citation check (2026-10-12)

Every identifier in the PRD/spec that the project text leans on was looked up (arXiv abstract
pages, Crossref records, the cited web pages). "Verified" means the identifier resolves to a
document with that title and the right authors/year. It does **not** mean I read the paper or
checked every claim attributed to it.

## Verified (identifier -> real document, title matches)

| PRD ref | Identifier | Found |
|---|---|---|
| [1] AICA reference architecture | arXiv:1803.10664 | Kott et al., *AICA Reference Architecture, Release 2.0* (2018, rev. 2023) |
| [2] | arXiv:1806.08657 | Théron, Kott et al., *Towards an Active, Autonomous and Intelligent Cyber Defense of Military Systems: the NATO AICA Reference Architecture* (2018) |
| [3] | arXiv:2304.12408 | Kott, *Autonomous Intelligent Cyber-defense Agent: Introduction and Overview* (2023) |
| [4] | arXiv:2201.11111 | Kott & Théron, *Doers, not Watchers: ...* (2022) |
| [7] Vyas, Mavroudis, Burnap | DOI 10.1145/3729213 | ACM Computing Surveys vol. 58 issue 1 (online Aug 2025; **print year 2026**, not 2025) |
| [9] SoK AIxCC | arXiv:2602.07666 | Zhang et al., Feb 2026, 21 authors |
| [10] DARPA announcement | darpa.mil/news/2025/aixcc-results | exists, 8 Aug 2025 |
| [11] CodeMender | deepmind.google blog | exists, 6 Oct 2025 |
| [12] AutoPatch | arXiv:2505.04195 | Seo et al., 2025 |
| [13] CAGE-4 scenario page | cage-challenge.github.io | exists; blue rewards are penalties only, incl. when green agents cannot work, and blocking can be penalised: **matches how the spec uses it** |
| [15] F5 virtual patching | helpnetsecurity.com 2026/09/02 | exists |
| [16] Cloudflare WAF ML | blog.cloudflare.com/making-waf-ai-models-go-brr | exists; **1519 us -> 275 us is total WAF-ML execution time** (5.5x), not inference alone (inference was ~247 -> ~56 us). The spec's "inline latency reality check" use is fine; do not call it inference time |
| [19] Han et al. SDN | DOI 10.1007/978-3-030-01554-1_9 | exists (GameSec/LNCS 2018) |
| [21] | arXiv:2410.17351 | Singh et al., 2024 |
| [22] Causally aware RL | DOI 10.1016/j.knosys.2024.112521 | Purves et al., Knowledge-Based Systems vol. 304 (2024) |
| [23] Morris | DOI 10.1002/ail2.125 | Morris, Procter, Wallbank, Applied AI Letters 6(3), 2025 |
| [24] MARL in cybersecurity | arXiv:2505.19837 | Landolt et al., 2025 |
| [25] Adversarial evasion vs ACD agents | DOI 10.1007/978-3-032-16165-9_2 | exists: Meijer, Vyas, Mavroudis, Juarez, LNCS (ESORICS 2025 workshops), online Apr 2026 |
| [26] C-MADF | arXiv:2604.04442 | Zhang, Goel, Ahmad, Apr 2026 |
| [27] Rosenberg et al. | DOI 10.1145/3453158 | ACM CSUR 54(5), 2021 |
| [28] Sim-to-real EDR | arXiv:2606.08168 | Prinos & Brush, Jun 2026 |
| CAI | arXiv:2504.06017 | exists, but its title is *CAI: An Open, Bug Bounty-Ready Cybersecurity AI* |

## Discrepancies to fix before any submission

1. **[20] wrong title.** arXiv:2310.07745 is *Deep Reinforcement Learning for Autonomous Cyber
   **Defence**: A Survey* (Palmer, Parry, Harrold, Willis). The PRD and `CLAUDE.md` say "...Cyber
   **Operations**: A Survey". The identifier is right; the title is not.
2. **[1] author list.** arXiv lists 12 authors in the order Kott, Théron, Drašar, Dushku, LeBlanc,
   Losiewicz, Guarino, Mancini, Panico, Pihelgas, Rzadca, De Gaspari. The PRD omits De Gaspari
   and reorders the rest.
3. **[7] year.** Online 2025, in the print issue of January 2026 (vol. 58); cite as 2025 (online)
   or 2026 (print) consistently.
4. **CETaS report (ref [6]): both attributions VERIFIED against the PDF (2026-10-25).** The report is
   *Autonomous Cyber Defence: A roadmap from lab to ops* (Andrew Lohn, Anna Knack, Ant Burke, Krystal
   Jackson; CSET Georgetown + CETaS; June 2023); the PRD omits the authors. I extracted the text of the
   PDF at the given URL with `pdftotext` and found:
   * **"turning all of the systems off"** - section 2.4 "Defining rewards" (PDF p. 24, printed p. 23):
     "If the agent's goal is simply to 'keep malware off of all systems,' the agent may achieve this
     goal by turning all of the systems off." It is the report's own hypothetical example of the
     alignment problem, not a measured result. The spec's wording is a fair paraphrase, but it is the
     example goal that matters: say "an agent told to keep malware off all systems", not "a badly
     specified objective" in general.
   * **"roughly 150x"** - section 2.3 "Computational requirements" (same page): "computing action-reward
     pairs was about 150 times as expensive as updating the neural network." Scope: the authors adapted
     the CAGE 2 winning agents' code (CybORG) and measured it themselves: reward calculation 3.15 ms on
     the CPU against 0.97 ms and 232 ms on the GPU for action choice and network update, with updates
     only every 20,000 steps; total cost was about the same on CPU and GPU (footnote 37: Xeon 2.3 GHz
     vs a Tesla V100). So it is one measurement on one simulator, and the report itself adds that more
     advanced agents "will certainly need much larger neural networks". It supports "the environment
     simulation, not the network update, dominates cost for CAGE-style agents"; it does not show that no
     GPU could ever be useful, and the spec's "cite that if anyone claims this needs a GPU budget"
     should be read that narrowly.

## Not checked

Refs [5], [8], [14], [17], [18], [20b]-[30] other than those above (news items, legal
references, the offensive-WAF papers), the Ulster fee note, and every quantitative claim made
*about* these papers. The PRD says all sources were "read during preparation"; that is the
PRD author's statement and I have not re-verified it. Search tools here cannot reach paywalled
publisher pages, so DOI checks rely on Crossref metadata.
