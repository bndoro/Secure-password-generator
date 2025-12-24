# Secure Password Generator (CSPRNG + Strength Meter)

Live Demo: (add your GitHub Pages link here)

A lightweight web app that generates passwords using a cryptographically secure RNG and provides a strength meter using entropy plus heuristic pattern checks.

## Features
- CSPRNG generation (`crypto.getRandomValues()`)
- Unbiased random selection (rejection sampling; avoids modulo bias)
- Category inclusion (ensures at least one from each selected set)
- Strength meter:
  - Entropy estimate
  - Pattern warnings (repeats, sequences, keyboard walks)
  - Crack-time estimates (illustrative online vs offline)

## How to run locally
Download the repo and open `index.html` in a modern browser.
