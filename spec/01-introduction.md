# 1. Introduction

## 1.1 Purpose

This document specifies crypto-pq 1.0. An implementer in any of the five languages MUST be able to
build a conforming implementation from this document and the standards it cites, without reading the
code of another language.

## 1.2 Audience

Maintainers, implementers of each language, auditors, and the authors of the public
documentation.

## 1.3 Structure

Part I is normative for every language. Part II holds one profile per language. A profile MAY add
requirements or narrow a choice that Part I leaves open; it MUST NOT contradict Part I. Where a rule
in this document is a project decision rather than a requirement of a cited standard, it carries a
reference of the form [D-nn] to its entry in [Appendix A](decisions.md).

## 1.4 Relation to the standards

crypto-pq implements published standards. This document does not restate them. For every algorithm
it names the standard and section that is authoritative, and it specifies only:

- the choices that a standard leaves to the implementation (for example parameter selection, the
  randomness source, error behaviour);
- the formats that no standard defines (the stateful state record and the tree cache);
- the API, the error model and the engineering rules shared by every implementation.

Where this document and a cited standard disagree on the algorithm itself, the standard governs and
the disagreement is a defect in this document.

## 1.5 How to read this document

This section is informative.

- Implementers of one language read Part I and the profile of their language (Sections [23](profiles/rust.md) to 27; profiles for other languages are maintained with their implementations).
  Part I gives the behaviour; the profile gives its form in the language.
- Users of the library read Sections [5](05-algorithms.md) to [13](13-hazmat.md) for the behaviour of each operation and Section [14.8](14-security.md#148-security-considerations) for
  the duties that the library leaves to its callers.
- Auditors start with Section [14](14-security.md), Section [11](11-stateful-signatures.md) and Section [19](19-conformance.md).
- Section [2](02-terminology.md) defines the terms and the notation. Each rule is stated once, and other sections refer to
  it by number: "[11.7](11-stateful-signatures.md#117-state-record-version-2)" is a section, and "[11.9](11-stateful-signatures.md#119-loading) item 4" is the fourth numbered item of Section [11.9](11-stateful-signatures.md#119-loading).
- A reference of the form [D-nn] leads to the decision log ([Appendix A](decisions.md)), which gives the rationale.
- The quick reference after the table of contents lists the tables that act as registries: algorithm
  values, object identifiers, error codes and byte formats.
