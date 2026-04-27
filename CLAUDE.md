# CLAUDE.md

Reference notes for an agent (or future-me) working in this repo. The subject is **how to write tagless-final software in Rust**, abstracted from a recent rewrite of an end-to-end test rig (orim → `tests/scenarios/` rust-script files driven by a `crates/orim_probe` DSL). What survives the port is what's worth remembering; specifics of orim are not.

The original work is Carette / Kiselyov / Shan, *Finally Tagless, Partially Evaluated*, J. Functional Programming 19(5), 2009. Oleg's web companion (`okmij.org/ftp/tagless-final/`) has every Haskell sketch you'll need; treat that as primary reading. This document is the part that survives when you take the pattern off Haskell, port it to Rust, and ship it for a pragmatic team.

## The shape of the thing

Tagless final, in one sentence: **a program is a polymorphic term over a typeclass, and an interpreter is an instance of that typeclass**.

Oleg's smallest example:

```haskell
class Symantics repr where
  int  :: Int -> repr Int
  add  :: repr Int -> repr Int -> repr Int
  lam  :: (repr a -> repr b) -> repr (a -> b)
  app  :: repr (a -> b) -> repr a -> repr b

three :: Symantics repr => repr Int
three = add (int 1) (int 2)
```

`three` is **one** value. Run it with `R` and you evaluate. Run it with `S` and you pretty-print. Run it with `P` and you partially-evaluate. The expression's commitment to a particular interpretation is the role of `repr` — and `repr` is a *type constructor* (`* -> *`), so the result type rides at the type level without ever touching a tag at runtime.

The contrast is the *initial* encoding: a GADT of constructors (`Int`, `Add`, `Lam`, `App`) you pattern-match. Initial gives you AST manipulation; final gives you fast, type-safe programs. Pick on use case.

## Why this is awkward in Rust

Rust does not have higher-kinded types. `repr :: * -> *` doesn't exist as a standalone abstraction — you can't declare `trait Symantics<repr<*>>`. The closest substitute is a **generic associated type** (GAT, stable since 1.65):

```rust
pub trait Symantics {
    type R<A> where A: Send + 'static;
    fn int(&self, x: i32)                              -> Self::R<i32>;
    fn add(&self, l: Self::R<i32>, r: Self::R<i32>)    -> Self::R<i32>;
}
```

`Self::R<A>` is "this interpreter's result type at `A`". The interpreter is the trait impl; the type-constructor goes through `Self`. You don't get HRTB over type parameters (so you can't write `for<S> S::R<…>` directly), but you do get one-interpreter-at-a-time polymorphism — enough for the pattern's bones.

Two things you lose vs Haskell:

  - **No HRTB-flavour quantification.** You can't call a polymorphic term universally — you have to pick `S` at every call site. Workaround: define a `Scenario` (or `Term`) trait with a generic method, then dispatch by trait-monomorphisation
  - **No partial-evaluation through closures.** Plan-style interpreters that need to walk the program have to invoke continuations with placeholder values; you can't peek inside an `FnOnce` without calling it

Neither is fatal. Both shape what's worth attempting.

## The Live interpreter — boxed futures, no apologies

The first interpreter you write is the one that *runs*. For an effectful DSL (HTTP, FS, shell, time) you almost certainly want it `async`. The cleanest Rust shape is:

```rust
pub struct Live { /* state */ }

pub type LiveR<A> = futures::future::BoxFuture<'static, anyhow::Result<A>>;

impl Symantics for Live {
    type R<A> = LiveR<A> where A: Send + 'static;

    fn int(&self, x: i32) -> Self::R<i32> {
        async move { Ok(x) }.boxed()
    }
    fn bind<A, B, F>(&self, m: Self::R<A>, k: F) -> Self::R<B>
    where
        A: Send + 'static, B: Send + 'static,
        F: FnOnce(A) -> Self::R<B> + Send + 'static,
    {
        async move {
            let a = m.await?;
            k(a).await
        }.boxed()
    }
}
```

That's it. `Pin<Box<dyn Future<Output = …>>>` per call, one heap allocation each. It's not zero-cost. **It also doesn't matter** for any program where the network round-trip dwarfs the dispatch — every test rig, every CLI driver, every infrastructure poking thing. Don't out-clever yourself trying to avoid the box. Nightly TAIT (`type R<A> = impl Future<…>`) gets you closer but explodes the moment two methods on the same impl return non-unifiable async blocks. Box. Move on.

Live's job is to be **boring and fast enough**. It's the path scenarios actually run. The smarter the interpreter, the more bugs hide in it; the simpler, the better the diagnostics.

## The Plan interpreter — free monad CPS

The second interpreter is the reason you chose tagless-final at all. If you only ship Live, you have ports-and-adapters with a fancier name. Plan is where the pattern earns its keep.

`Plan` reifies the program as a tree of nodes — one variant per effect, each carrying the effect specification *and* a continuation `Box<dyn FnOnce(R) -> PlanNode<A>>`. Concretely, for an effect `http(url) -> Response`:

```rust
pub enum PlanNode<A: 'static> {
    Pure(A),
    Http {
        url: String,
        cont: Box<dyn FnOnce(Response) -> PlanNode<A> + Send + 'static>,
    },
    /* one variant per effect in your DSL */
}
```

`bind` walks the tree and pushes the new continuation past the leaves:

```rust
impl<A: Send + 'static> PlanNode<A> {
    pub fn bind<B: Send + 'static>(self, k: impl FnOnce(A) -> PlanNode<B> + Send + 'static) -> PlanNode<B> {
        match self {
            PlanNode::Pure(a) => k(a),
            PlanNode::Http { url, cont } =>
                PlanNode::Http { url, cont: Box::new(move |r| cont(r).bind(k)) },
            // … same shape per variant …
        }
    }
}
```

This is the **free monad** in Rust: each effect is a functor cell, `bind` is fmap-cum-join. You write one variant per effect because Rust has no HKT-over-functors abstraction; the typing doesn't care, you just have to type out the boilerplate.

To **render** a Plan to text, k6, or anything else, walk the tree. At each effect you have an effect description (rendered straight) and a continuation you must call to keep going. Calling means producing a stub `R` value — `Response { status: 200, body: vec![] }`, `ProcessOut { status: 0, … }`, etc. Stubs let traversal proceed but mean: **renderers only follow the happy path**. A scenario that branches on response data is partially observable to a renderer. For most regression suites this is fine; for a partial-evaluator it's not.

The deep lesson: closures in continuations are a fundamental traversal hazard. You either accept it (stubs), require user code to be branch-free (linting), or rebuild the DSL with explicit `match`-style branching as a DSL primitive. The first option is what you ship; the third is academically correct and unbearable to write.

## The async/await escape hatch

A pure tagless-final scenario uses only `pure`, `bind`, and effect methods:

```rust
fn login_flow<S: Symantics>(s: &S) -> S::R<Session> {
    s.bind(s.http_post("/login", credentials), |resp|
        s.bind(s.assert_status(resp, 200), |_|
            s.parse_session(resp)))
}
```

This **works** under `Live` and `Plan` and any future interpreter. It is also unbearable to write by hand at scale. A typical end-to-end scenario has ten to thirty steps; nesting them by hand gives you a right-rotated tower that nobody will read.

Two responses, in increasing surrender to ergonomics:

**(1) A do-notation macro.** A `do!` macro desugars a flat block into nested `bind`s:

```rust
probe_do! { s ;
    let resp  = s.http_post("/login", credentials) ;
    let _     = s.assert_status(&resp, 200) ;
    let sess  = s.parse_session(&resp) ;
    s.pure(sess)
}
```

The macro is twenty lines of `macro_rules!`. It takes `$s:ident` (not `$s:expr`) so it can shadow the binding inside each generated closure — that's the trick that makes the borrow checker happy when user code references `&s` literally. The expansion is the right-rotated tower you would have typed; you just don't see it.

**(2) Take the L on polymorphism.** Write the body in `async`/`await` over `Live::R`, accept that the scenario only runs under Live, declare the trait shape sufficient on its own. Most production code lives here, and if you're honest, that's fine. The encoding still constrains you to go through DSL methods (no `std::process::Command` escape hatches) — which is most of the value.

In the orim rewrite both forms ship side by side: a trait + Plan + macro for the demo of the encoding, then async/await for the bulk of the suite. Authors get readable code; the architectural property "every effect is in the trait" survives.

## When you write a new effect

Every external thing your scenarios touch becomes a method. If you find yourself reaching for `std::process::Command` or `tokio::fs` from inside a scenario, that effect doesn't exist in your DSL yet — go add it. The trait expands, the Live impl handles it, the Plan impl records it. Cost per effect: ~15 lines. Benefit: every renderer / dry-run / replay continues to work.

The discipline is what makes the tagless-final pattern *actually* tagless-final, as opposed to a typeclass over reqwest. If you slip and add `Command::new` inside one scenario, a future renderer can no longer faithfully reproduce that scenario, and the encoding has lied.

## Choosing the bound on `A`

`type R<A> where A: Send + 'static` is what you'll write 95% of the time. It pins:

  - `Send` because Live's futures are sent across tokio worker threads
  - `'static` because closures stored inside `Plan` continuations can't borrow

Loosening either is possible but tedious. If you find yourself needing `A: ?Send` (single-threaded interpreter, e.g. in a wasm context), fork the trait. If you need `A: 'a` (borrowed values), you give up most of the encoding. Pick the bound that lets your interpreters live and resist parameterising further until a real use case demands it.

## What this gives you, concretely

  - **One scenario, many interpreters.** The same source runs against a real deployment (Live), prints an AST trace (Plan), or could render to k6 / doc / mock harnesses (future interpreters)
  - **Every effect goes through the type system.** A scenario that doesn't touch the filesystem can't accidentally start touching it without changing its trait bounds
  - **Test-rig logic is portable across runtimes.** Want to run the same scenario in a single-threaded WASM mock? Swap interpreters, not scenarios
  - **The discipline gives you reviewable diffs.** Adding an effect shows up as a trait method addition, an impl line per interpreter, and the call sites that use it — instead of a sprawl of inline `Command::new` calls scattered across files

What it costs:

  - Boxed futures (negligible at I/O scale, real at hot-loop scale)
  - One impl block per interpreter per effect (mechanical, but tedious)
  - A `do!` macro to keep scenarios readable (twenty lines once)
  - Acceptance that some Rust-specific limitations (HKT, branching-through-closures) are not going to disappear because you wrote a clever trait

## When NOT to do this

  - Your "DSL" is one HTTP method. You don't need an encoding; you need a function
  - You only ever ship one interpreter and have no plausible second. The encoding is dead weight; ports-and-adapters with `#[async_trait]` is what you want
  - Your scenarios genuinely need heavy branching on effect outputs — the partial-observability of Plan will frustrate you, and the cost of working around it (CPS-encoded `if`/`match` as DSL primitives) is higher than the value of the encoding

## Operational instructions for an agent working here

If you're asked to *implement* tagless-final in a Rust codebase:

  1. Start with the trait. Methods minimal and orthogonal — favour `bind`/`pure`/`seq` plus one method per concrete effect. Resist composite methods (`http_with_retry_and_metrics`); those compose at the helper layer
  2. Implement Live first. `R<A> = BoxFuture<Result<A>>`. Get a single effect (HTTP) end-to-end before adding the rest
  3. Implement Plan only if you have a concrete second use case (dry-run rendering, k6 emit, doc generation). Don't speculate
  4. Add the `do!` macro the moment you have a scenario with more than three steps. Without it, contributors will write `Command::new` because nesting `bind` is unreadable
  5. Document the bound on `A` at the trait. Future readers won't reverse-engineer it
  6. When adding a new effect, do it in this order: trait method, Live impl, Plan impl (or stub), one scenario that uses it, doc note in the contributor guide

If you're asked to *read* tagless-final code and reason about it:

  1. The trait is the language. Read it first; the methods are its vocabulary
  2. Each interpreter is an evaluation strategy. Live runs; Plan inspects; future ones might cache, replay, or distribute
  3. Scenarios are programs. They should look like recipes, not like Rust gymnastics. If they don't, the macro is missing or the trait is too low-level

## Reading list

  - Carette, Kiselyov, Shan. *Finally Tagless, Partially Evaluated.* JFP 19(5), 2009. The paper
  - `okmij.org/ftp/tagless-final/` — Oleg's catalogue, with code
  - Kiselyov, *Typed Tagless Final Interpreters* (lecture notes, 2010). The pedagogical entry
  - Swierstra. *Data Types à la Carte*, JFP 18(4), 2008. The free-monad sibling — read this when Plan starts to feel like the wrong shape

The rest is implementation. The encoding gives you the spine; everything else is just typing.
