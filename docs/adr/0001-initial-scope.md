# ADR 0001: Start with an offline deterministic vertical slice

**Status:** Accepted

## Context

REPRISE needs trustworthy authorization semantics and evidence contracts before
adding an LLM, live cluster credentials, or automated mutation. The proposed
project is large enough that an all-at-once implementation would hide unsafe
assumptions.

## Decision

Start with a standard-library-compatible offline fixture pipeline:

1. load bounded sanitized evidence;
2. detect one suspicious change/access sequence;
3. enumerate every supported RBAC grant path;
4. emit evidence-linked JSON and Markdown artifacts;
5. test redundant paths and matching edge cases.

Keep the code pure and deterministic where possible. Treat unsupported
semantics as explicit coverage warnings.

## Consequences

The first milestone is runnable without Docker, Kubernetes, PostgreSQL, or an AI
provider. It is less visually impressive, but it creates a testable security
foundation and makes the later agent and lab-validation work measurable.
