---
name: False Positive / False Negative Report
about: Report a scanner accuracy problem
title: '[ACCURACY] '
labels: accuracy
assignees: ''
---

## Type

- [ ] False Positive (finding reported that doesn't exist)
- [ ] False Negative (real vulnerability not detected)

## Target URL

The URL that was scanned (you may anonymize the domain if needed).

## Finding Title

The finding title as shown in the report.

## Expected Behaviour

What the scanner should report for this target.

## Actual Behaviour

What the scanner reported.

## Evidence

What you observed when manually checking the finding (e.g., the response body from the URL, DNS query output, etc.)

## Scanner Module

- [ ] DNS Checker
- [ ] SSL/TLS Checker
- [ ] Header Analyzer
- [ ] Technology Detector
- [ ] CVE Checker
- [ ] Content Analyzer
- [ ] Other

## Reproduction

Steps to reproduce (scan the URL and observe the finding).
