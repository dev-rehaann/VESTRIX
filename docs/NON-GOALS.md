# Non-Goals — Explicit Scope Boundaries

This list is maintained deliberately, not deleted as the project matures. A living non-goals list is part of the credibility story: RuView lost credibility retracting an inflated "100% detection" claim; a public, maintained non-goals section is the antidote.

## What Vestrix is not trying to be

- **Not** matching RuView's ~105-module breadth. Depth in one defensible niche (security + forensics + SOC integration) beats breadth across many shallow ones.
- **Not** a general-purpose WiFi sensing research platform. Gesture recognition, vital-signs sensing, pose estimation, and similar applications stay out of scope unless they directly serve intrusion detection.
- **Not** claiming production maturity that hasn't been earned. Every benchmark shipped is real, dated, and reproducible — including on the days the numbers aren't flattering.
- **Not** claiming novelty in WiFi CSI sensing, ESP32 CSI extraction, or ML-classified presence detection. These are established prior art (see [`standards-alignment.md`](standards-alignment.md)). Vestrix's claim is narrower: integrating security-first design, forensic chain of custody, and native SOC/SIEM correlation around CSI sensing.
- **Not** claiming adversarial robustness that has not been tested. Published attack classes such as context-aware spoofing, signal manipulation, and CSI-targeted adversarial perturbation are known limitations, not solved problems.

## Revisit triggers

Revisit this file when:

- A release adds a capability that could be mistaken for scope creep.
- A benchmark result would look better if a caveat here were quietly removed. That temptation is a signal that the caveat should remain visible.
