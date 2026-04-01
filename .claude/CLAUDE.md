# AI-Safe Coding Spec v2.0

## Build & Verify

Every change must pass before output:

```bash
cargo check
cargo test
cargo clippy -- -D warnings
```

For non-Rust projects, use the equivalent commands (`go vet`, `npm run lint`, `pytest`, etc.). If any command fails, fix before outputting.

After every change, include execution evidence in your response:
```
Working Directory: src-tauri/
cargo check   → success
cargo test    → 12 passed / 0 failed
cargo clippy  → clean
```

If execution cannot be verified, state that explicitly. Do not claim success without evidence.

## Architecture

```
Group code by domain: /auth, /billing, /vpn-engine
Do not use /utils, /helpers as top-level structure.
```

- Each module has a single responsibility. Orchestration layers must not contain business logic.
- Handlers → Services → Data Layer. Never skip layers.
- No premature abstraction: extract only when duplication appears a second time.
- No unnecessary indirection. If a wrapper adds no value, remove it.

## Naming & Conventions

- Names must precisely reflect responsibility. Banned top-level names: `utils`, `helpers`, `common`, `misc` (scoped names like `auth_helpers` are acceptable).
- Follow target language idioms strictly. Do not leak style from other languages (e.g., no Java-style getters/setters in Rust, no snake_case in TypeScript).

## Code Communication

- Code must be self-explanatory. Comments explain **WHY**, never WHAT.
- Remove all redundant comments (e.g., `// increment counter` above `counter += 1`).

## Testing

- Critical paths and boundary conditions must have test coverage.
- Dependencies must be injectable or mockable. No hidden state.
- Use the idiomatic test framework of the target ecosystem (Rust → `#[cfg(test)]`, Go → `testing`, JS → vitest/jest).
- All tests must pass. Fix failing tests — never skip or ignore them. Never introduce regressions.

## Compilation & Lint (Hard Gate)

- Code must compile successfully. Resolve all compiler errors before output.
- Fix all actionable warnings: type errors, dead code, unused variables/imports, unsafe operations.
- Do not suppress warnings to pass checks (`#[allow(...)]`, `@SuppressWarnings`, `// eslint-disable`, etc.).
- Output must be free of errors and warnings under standard IDE configuration.

## External API & Anti-Hallucination

This is one of the most important rules:

- External API calls must be verified via type definitions or official documentation. Otherwise mark as `// UNVERIFIED`.
- **Never fabricate** APIs, fields, methods, or behaviors.
- If API behavior is uncertain, types are bypassed (`as any`, unsafe casts), or errors are suppressed → **stop immediately**, explain the situation, and do not continue.
- All unknowns must be explicitly surfaced. No implicit assumptions.

## Runtime Boundaries

- Validate dynamic data at boundaries: schema validation, explicit type checks, fail-fast on invalid input.
- Deterministic data must be generated at build time. Use runtime generation only when necessary.
- Cache expensive operations: in-memory for hot paths, persistent/CDN for static assets.
- Optimization must be justified by real need, not speculation.

## Error Handling

- Fail fast and explicitly. No silent failures.
- Error messages must include actionable context (what failed, what input, what was expected). Never use generic messages like `"Something went wrong"`.
- Error handling at boundaries must be explicit.
- Retries must be bounded. Only retry idempotent operations.

## Determinism

- Same input must produce same output.
- No hidden state. No implicit side effects.
- Prefer pure functions.

## Simplicity First

- Choose the simplest correct solution. No unnecessary abstraction. No speculative design.
- If a simple approach solves the problem, do not use a complex one.

## Missing Information Protocol

If I have not provided enough information (API contracts, type definitions, expected behavior):

- **Do not guess and produce a full implementation.**
- Ask me what is missing.
- Or provide a partial solution with unknowns explicitly marked: `// TODO: need to confirm X`.

## CI Definition

When defining CI jobs, always specify: job name, execution environment, dependencies, exact commands.

Bad:
```
Added cargo-test job.
```

Good:
```
Job: cargo-test
Environment: Ubuntu latest
Dependencies: stable Rust toolchain
Commands: cd src-tauri && cargo test
```

## Common Mistakes to Avoid

- Do not generate code that "looks right" but has not been verified.
- Do not fabricate API signatures when uncertain.
- Do not use `any`, careless `unwrap()`, or empty `catch` blocks to bypass type safety.
- Do not suppress warnings to make checks pass.
- Do not assume CI will succeed — define every step explicitly.
- Do not wait to be asked for execution evidence — include it proactively with every change.

