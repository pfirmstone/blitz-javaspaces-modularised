# blitz-javaspaces-modularised → JGDMS + DirtyChai Modernisation Context

**Document version:** 1.0  
**Date:** 2026-05-09  
**Reference document:** `pfirmstone/JGDMS` — `JGDMS/docs/Big picture security architecture/AI_Agent_JGDMS-GrantPermission-RoleManagement-context_8.md` (v19)  
**Repositories:**
- Blitz (this repo): https://github.com/pfirmstone/blitz-javaspaces-modularised
- JGDMS: https://github.com/pfirmstone/JGDMS
- DirtyChai: https://github.com/pfirmstone/DirtyChai

---

## 1. Purpose

This document records the findings of a deep-dive assessment of the work required to
update blitz-javaspaces-modularised to:

1. Use the latest features of **JGDMS** (JGDMS-STD-001, JGDMS-STD-002, JGDMS-STD-003 v3.1)
   and **DirtyChai** (sealed `Subject` hierarchy, `@AtomicSerial`, three-layer policy stack,
   `SpiffeCredentialManager`, SCAP pipeline integration).
2. Lock down the service against **Denial-of-Service (DoS)** vectors identified in the
   JGDMS security architecture.

The document is structured as an AI-agent context file — it is intended to be read by
a future agent session to resume work without loss of context.

---

## 2. Codebase Snapshot (as assessed)

| Item | Value |
|---|---|
| Java target | 1.6 (`maven-compiler-plugin source/target = 1.6`) |
| Jini/River dependency | `net.jini:jsk-*:2.2.1`, `org.apache.river:outrigger:2.2.1` |
| Maven plugin vintage | 2010–2013 (`maven-jar-plugin:2.3`, `maven-compiler-plugin:2.3.2`) |
| Security manager | `RMISecurityManager` (installed at startup — removed in Java 17) |
| Authentication | JAAS `LoginContext` + `Subject.doAsPrivileged` |
| Wire serialization | Raw `java.io.Serializable` throughout (108 classes) |
| Proxy trust | `BasicProxyPreparer` (no-op) for all external proxies |
| Policy | None configured; relies on JVM-default open policy |
| SPIFFE/SPIRE | None |
| `@AtomicSerial` | None |
| Module system | Maven modules only; no `module-info.java` |
| SCAP pipeline | None |
| DoS caps | No wait-time caps, no bounded queues, `Lease.FOREVER` allowed by default |

### 2.1 Maven module layout

```
blitz-javaspaces-modularised/
├── blitz-common/    – shared utilities (Logging, LifecycleRegistry, stats, jini/util)
├── blitz-proxy/     – client-side smart proxy, wire types, proxy verifier
├── blitz-service/   – server-side implementation (SpaceImpl, BlitzServiceImpl, BerkeleyDB)
└── blitz-ui/        – admin dashboard tools
```

### 2.2 Key source files

| File | Role |
|---|---|
| `blitz-service/.../remote/BlitzServiceImpl.java` | Service entry point; lifecycle, export, JoinManager |
| `blitz-service/.../SpaceImpl.java` | Core space backend (entry store, lease, txn, notify) |
| `blitz-service/.../disk/Disk.java` | BerkeleyDB I/O layer |
| `blitz-service/.../disk/WriteDaemon.java` | Single async write thread |
| `blitz-service/.../notify/EventQueue.java` | Event dispatch queue |
| `blitz-service/.../task/Tasks.java` | Thread pool for task dispatch |
| `blitz-service/.../remote/transport/ServerSessionHandler.java` | MINA/NIO transport |
| `blitz-proxy/.../remote/BlitzProxy.java` | Smart proxy (client side) |
| `blitz-proxy/.../remote/ConstrainableBlitzProxy.java` | Constrainable variant |
| `blitz-proxy/.../remote/ProxyVerifier.java` | `TrustVerifier` implementation |
| `blitz-proxy/.../mangler/MangledEntry.java` | Wire-crossing entry serialization |
| `src/main/resources/config/blitz.config` | Primary config (TCP, no auth) |
| `src/main/resources/config/blitz.ssl.config` | SSL/TLS config (JAAS, X.509) |

---

## 3. JGDMS Architecture Background (relevant to Blitz)

### 3.1 Five-Host SCAP Pipeline (JGDMS-STD-002)

```
Host 1 — Jini Lookup Service       (passive registry)
Host 2 — BAE Pool                  (SELinux-isolated bytecode analyser; stateless)
Host 3 — Verdict Registry          (holds client-trusted signing key; no bytecode parsing)
Host 4 — Codebase Downloader       (proactive; only host with outbound internet)
Host 5 — JFR Telemetry Service     (reacts to VirtualThreadPinned events)
```

**Before any proxy is unmarshalled**, `ProxyCodebaseSPI` hashes the JAR and queries
Host 3 for a `RegistryVerdict`. A single `DANGEROUS` verdict condemns the codebase.

The BAE analyses per JAR:
- `ClinitBlockingVisitor` — blocking `<clinit>` paths; `BLOCKING`, `BLOCKING_GUARDED`,
  `BLOCKING_DECLARED`, `NATIVE_OPACITY`, `CLEAN`, `CYCLE`
- `AtomicSerialComplianceVisitor` — `@AtomicSerial` protocol adherence (see §3.3)
- `JarAnalyzer` — reads `META-INF/PERMISSIONS.LIST`; upgrades `BLOCKING_GUARDED` →
  `BLOCKING_DECLARED` (`DANGEROUS`) when the guarding permission class is declared in `PERMISSIONS.LIST`

### 3.2 Three-Layer Policy Stack

```
DynamicPolicyProvider          (outermost — per-proxy, GC-scoped grants)
    └── RemotePolicyProvider   (djinn-wide grants from InMemoryPolicyService)
            └── SpiffePolicyFile       (bootstrap grants from HTTPS server)
                    └── (minimal local grant: SPIRE socket only)
```

Each layer implements `ScalableNestedPolicy`. Grants flow upward through the stack.

| Layer | Grant issuer | Grant lifetime | Revocation |
|---|---|---|---|
| `SpiffePolicyFile` | Bootstrap HTTPS server (operator) | JVM lifetime | `refresh()` on SVID rotation |
| `RemotePolicyProvider` | `InMemoryPolicyService` via administrator | Djinn session | `replace()` via `RemoteEvent` |
| `DynamicPolicyProvider` | Any caller holding `GrantPermission` | Proxy reachability | Automatic on GC |

### 3.3 `@AtomicSerial` Compliance (JGDMS-STD-001)

Every `Serializable` class crossing a JERI wire must comply with six rules:

- **RULE-1** Annotated `@AtomicSerial`
- **RULE-2** Public `(GetArg)` constructor
- **RULE-3** Static check method called **before** any field is set in the GetArg constructor
- **RULE-4** All `Object`-returning `GetArg.get()` calls must be type-checked
- **RULE-5** `serialForm()` + `serialPersistentFields` declared for classes with instance fields
- **RULE-6** Static `serialize(PutArg, T)` method

Violations → `DANGEROUS` verdict → codebase refused by all JGDMS clients.

### 3.4 DirtyChai Identity Layers

DirtyChai formalises three distinct identity layers (JGDMS-STD-003 v3.1 §3.1):

| Layer | Type | Carrier | Survives `doPrivileged` | Established by |
|---|---|---|---|---|
| Process worker | `WorkerSubject` (sealed, `SpiffeSubject` only) | Baked into `ProtectionDomain` at class load time | **Yes** — in every domain | DirtyChai `SpiffeCredentialManager` |
| Remote process | `WorkerSubject` principals in remote PDs | Serialized ACC over JERI | No | JERI dispatcher (receiving side) |
| User | `UserSubject` (final) | `SCOPED_SUBJECT ScopedValue<Subject[]>` | **Yes** — injected into `privilegedContext` | JERI dispatcher / `Subject.callAs` |

**Routing rules (sealed hierarchy):**

| Method | Accepts | Rejects |
|---|---|---|
| `Subject.doAs(Subject, PrivilegedAction)` | Vanilla `Subject`, `null` | `UserSubject` → must use `callAs`; `WorkerSubject` → `IllegalArgumentException` |
| `Subject.callAs(Subject, Callable)` | `UserSubject`, vanilla `Subject` | `WorkerSubject` at runtime |
| `Subject.callAs(Callable, UserSubject...)` | `UserSubject[]` | `WorkerSubject` at compile time |

### 3.5 `AbstractJiniService` — Reference Implementation Pattern

JGDMS services extend `AbstractJiniService` from `jgdms-service-support`. Key behaviours:

- **SPIFFE path (`loginContext == null`):** `doStart()` called directly. SPIFFE `WorkerSubject`
  is ambient (baked into `ProtectionDomain`s by `SecureClassLoader` / `SpiffeCredentialManager`).
  Per-request `UserSubject` established by `BasicInvocationDispatcher.invokeWithClientSubject()`
  via `Subject.callAs(userSubject, action)`.
- **JAAS path (`loginContext != null`):** `loginContext.login()` then
  `Subject.callAs(loginSubject, callable)` to run `doStart()`. Subject is a `UserSubject`.
- Uses `ReadyState` (from `org.apache.river.thread.ReadyState`) to guard all service calls
  before start and after shutdown — equivalent to Blitz's `stopBarrier()`.

### 3.6 VerifyingProxyPreparer

`VerifyingProxyPreparer(boolean verify, MethodConstraints constraints, Permission[] permissions)`

- Replaces `BasicProxyPreparer` as the trust enforcer for received proxies.
- Advisory permissions path: calls `Security.grant(proxyClass, perms)` → soft failure on
  `UnsupportedOperationException`.
- `Security.grant()` enforces the three-way `GrantPermission` intersection (declared ∩
  authorised ∩ SPIFFE principal-scoped).

### 3.7 DoS Risk Categorisation for `GrantPermission`

| Category | Examples | Recommendation |
|---|---|---|
| Safe to delegate | `FilePermission` to specific data dirs | Advisory path appropriate |
| Requires care | `RuntimePermission("createVirtualThread")` | Scope to specific SPIFFE principal |
| **DoS risk** | `SocketPermission`, `NativeInvocationPermission`, `createVirtualThread` | BAE flags as `DANGEROUS` if in `PERMISSIONS.LIST` without guard |
| Never delegate | `PolicyPermission("Remote")`, `GrantPermission` itself, `AllPermission` | Must not appear in delegatable grants |

---

## 4. Gap Analysis

### 4.1 Build and Dependency Infrastructure

**Current state:** Maven targeting Java 1.6; plugin versions from 2010–2013; coordinates are
Apache River 2.2.1 (`net.jini:jsk-*`, `org.apache.river:outrigger`); `com.sun.jini.*`
internal packages used throughout; `org.rioproject` dependency for test infrastructure.

**Required changes:**

1. Replace all `net.jini.*` and `org.apache.river.*` Maven coordinates with JGDMS equivalents.
   JGDMS uses the same package namespaces but different Maven groupIds/artifactIds under
   `au.net.zeus.jgdms.*`.
2. Replace every `com.sun.jini.*` import with its JGDMS equivalent:
   - `com.sun.jini.start.LifeCycle` → `org.apache.river.start.lifecycle.LifeCycle`
   - `com.sun.jini.start.NonActivatableServiceDescriptor` → JGDMS equivalent
3. Upgrade compiler target to Java 21; update all Maven plugin versions to current stable.
4. Remove `org.rioproject` dependency (not part of JGDMS ecosystem).
5. Add `module-info.java` to each Maven module (see §4.9).

---

### 4.2 Service Lifecycle — `BlitzServiceImpl`

**Current state:**

```java
// BlitzServiceImpl.java — current
public class BlitzServiceImpl implements ServerProxyTrust, ProxyAccessor, BlitzServer {
    private void init(String[] anArgs, boolean doExport) {
        if (doExport) {
            if (System.getSecurityManager() == null)
                System.setSecurityManager(new RMISecurityManager()); // REMOVED IN JAVA 17
        }
        // ...
        if (theLoginContext != null) {
            theLoginContext.login();
        }
        doPriv(new PrivilegedInitImpl(doExport)); // wraps Subject.doAsPrivileged
    }

    private Object doPriv(PrivilegedExceptionAction aPAE) throws Exception {
        if (theLoginContext != null) {
            return Subject.doAsPrivileged(theLoginContext.getSubject(), aPAE, null); // BLOCKED in DirtyChai for UserSubject
        } else
            return aPAE.run();
    }
}
```

**Problems:**
- `RMISecurityManager` does not exist in DirtyChai's JDK (removed in Java 17).
- `Subject.doAsPrivileged` is blocked in DirtyChai when the subject is a `UserSubject`.
  DirtyChai's routing rule: `UserSubject` must use `Subject.callAs`, not `doAs`/`doAsPrivileged`.
- The class does not extend `AbstractJiniService`; it reimplements lifecycle boilerplate
  (`JoinManager`, `Exporter`, `ReadyState`/`stopBarrier`, `ServiceID`) redundantly.
- Static `theServiceImpl` reference to prevent GC is handled automatically by `AbstractJiniService`.
- All activation code (`ActivationID`, `ActivationSystem`, `ActivationExporter`,
  `Activatable`) is unnecessary — JGDMS services are non-activatable.

**Required changes:**

1. Replace `BlitzServiceImpl` with a class extending `AbstractJiniService`.
2. Implement template methods `createProxy(Object stub, Uuid id)` and
   `getServiceInterfaces()`.
3. Override `onExported(Object stub)` to give the stub reference to `SpaceImpl` and
   the proxy factories.
4. Choose SPIFFE or JAAS path (see §4.3).
5. Remove all `Activatable` / `ActivationExporter` / `ActivationID` code.
6. Remove `RMISecurityManager` installation.
7. Replace `stopBarrier()` with `ReadyState` from `org.apache.river.thread.ReadyState`.

---

### 4.3 Authentication and Identity

**Current state:**
- `blitz.ssl.config` uses JAAS `LoginContext("org.dancres.blitz.Server")` with a
  `KeyStores.getX500Principal` TLS identity.
- `Subject.doAsPrivileged(loginContext.getSubject(), action, null)` used at startup.
- No SPIFFE/SPIRE integration; no `WorkerSubject`/`UserSubject` distinction.

**Required changes — choose one path:**

#### Path A — SPIFFE/SPIRE (recommended for JGDMS production deployments)

1. Remove `loginContext` config entry (set to `null` in `AbstractJiniService`).
2. Deploy a SPIRE agent on the Blitz host. Configure the SVID URI, e.g.
   `spiffe://example.org/blitz/space`.
3. `SpiffeCredentialManager.start()` (DirtyChai) registers the `SpiffeSubject`
   (a sealed `WorkerSubject`) into every `ProtectionDomain` at class load time via
   `SecureClassLoader`. No Blitz code change needed for this step.
4. `SslServerEndpoint` / `SslEndpointImpl` automatically uses `SpiffeSubjectHolder`
   to find the TLS credential — no explicit `Subject.doAs` wrapper.
5. On each JERI dispatch, `BasicInvocationDispatcher.invokeWithClientSubject()`
   establishes the per-request `UserSubject` via `Subject.callAs(userSubject, action)`,
   visible as `Subject.current()` inside Blitz service methods.
6. Update `blitz.ssl.config`: replace JAAS-based `serverUser` / `serverId` with
   SPIFFE method constraints.

#### Path B — Traditional JAAS (legacy compatibility)

1. Keep `loginContext` in config.
2. Replace `Subject.doAsPrivileged(loginSubject, action, null)` with
   `Subject.callAs(loginSubject, () -> { doStart(); return null; })`.
   Note: `loginSubject` must be treated as a `UserSubject` (not a `WorkerSubject`).
3. Keep SSL `KeyStores`-based config.

---

### 4.4 Proxy Trust and Preparation

**Current state:**
All preparers are no-ops:
```java
// blitz.config
notifyPreparer         = new BasicProxyPreparer();
recoveredNotifyPreparer= new BasicProxyPreparer();
txnPreparer            = new BasicProxyPreparer();
recoveredTxnPreparer   = new BasicProxyPreparer();
activationIdPreparer   = new BasicProxyPreparer();
activationSysPreparer  = new BasicProxyPreparer();
```

**Problems:**
- `BasicProxyPreparer` accepts any proxy without authentication or integrity verification.
- A malicious transaction manager or event listener can be injected without detection.
- `ProxyVerifier` exists in `blitz-proxy` but is not wired to a `VerifyingProxyPreparer`.

**Required changes:**

1. Replace `BasicProxyPreparer` with `VerifyingProxyPreparer` for all external proxies:
   ```java
   // blitz.config — updated
   notifyPreparer = new VerifyingProxyPreparer(true,
       new BasicMethodConstraints(
           new InvocationConstraints(Integrity.YES, null)), null);
   txnPreparer = new VerifyingProxyPreparer(true,
       new BasicMethodConstraints(
           new InvocationConstraints(Integrity.YES, null)), null);
   ```
2. For recovered proxies, use the same constraints.
3. Remove `activationIdPreparer` and `activationSysPreparer` (activation removed).
4. For client-supplied `RemoteEventListener` (received during `notify()` registration),
   require that the listener's workload SPIFFE principal matches a trusted pattern.
5. Add `META-INF/PERMISSIONS.LIST` to `blitz-proxy` JAR (see §4.5).

---

### 4.5 Wire Serialization — `@AtomicSerial` Migration

**This is the dominant cost item.**

108 classes in `blitz-service` and `blitz-proxy` use `java.io.Serializable`. Without
`@AtomicSerial` compliance, the BAE's `AtomicSerialComplianceVisitor` will flag
`blitz-proxy` as `DANGEROUS` and no JGDMS client will unmarshal Blitz proxies.

Additionally, DirtyChai enforces `SerialObjectPermission` in
`ObjectInputStream.readOrdinaryObject()`. Classes not declared in the security policy
are blocked from deserialisation entirely.

**Migration template:**

```java
import au.zeus.jdk.io.AtomicSerial;
import au.zeus.jdk.io.GetArg;
import au.zeus.jdk.io.PutArg;

@AtomicSerial
public class MangledEntry implements Serializable {

    // RULE-5: serialPersistentFields
    private static final ObjectStreamField[] serialPersistentFields = {
        new ObjectStreamField("type",   String.class),
        new ObjectStreamField("fields", MangledField[].class),
    };

    private final String type;
    private final MangledField[] fields;

    // RULE-2: (GetArg) constructor
    public MangledEntry(GetArg args) throws IOException {
        // RULE-3: static check BEFORE any field assignment
        MangledEntry.check(args);
        this.type   = (String)         args.get("type",   null);  // RULE-4: type-checked
        this.fields = (MangledField[]) args.get("fields", null);  // RULE-4: type-checked
    }

    // RULE-6: static serialize method
    static void serialize(PutArg args, MangledEntry t) throws IOException {
        args.put("type",   t.type);
        args.put("fields", t.fields);
        args.writeThrow();
    }

    // RULE-3: static check method
    private static void check(GetArg args) throws IOException {
        // validate invariants; throw InvalidObjectException on violation
        String type = (String) args.get("type", null);
        if (type == null) throw new InvalidObjectException("type is null");
        // ...
    }

    // existing constructors and methods unchanged ...
}
```

**Priority classes for migration (wire-crossing):**

| Class | Location | Priority |
|---|---|---|
| `MangledEntry` | `blitz-proxy` | HIGH — every space operation |
| `MangledField` | `blitz-proxy` | HIGH |
| `BlitzProxy` | `blitz-proxy` | HIGH — main smart proxy |
| `ConstrainableBlitzProxy` | `blitz-proxy` | HIGH |
| `AdminProxy` | `blitz-proxy` | HIGH |
| `ConstrainableAdminProxy` | `blitz-proxy` | HIGH |
| `TxnParticipantProxy` | `blitz-proxy` | HIGH |
| `ConstrainableTxnParticipantProxy` | `blitz-proxy` | HIGH |
| `LeaseImpl` | `blitz-proxy` | HIGH |
| `ConstrainableLeaseImpl` | `blitz-proxy` | HIGH |
| `LeaseResults` | `blitz-proxy` | HIGH |
| `AvailabilityEventImpl` | `blitz-proxy` | HIGH |
| `SpaceNotifyUID` | `blitz-proxy` | HIGH |
| `SpaceEntryUID` | `blitz-proxy` | HIGH |
| `UIDImpl` | `blitz-proxy` | HIGH |
| `EntryViewUID` | `blitz-proxy` | MEDIUM |
| `SpaceTxnUID` | `blitz-proxy` | MEDIUM |
| `ViewResult` | `blitz-proxy` | MEDIUM |
| `MatchSetImpl` | `blitz-proxy` | MEDIUM |
| `EntryChit` | `blitz-proxy` | MEDIUM |

`MarshalledObject` usage in `BlitzServiceImpl` (startup args unmarshalling) should be
replaced with `MarshalledInstance` from JGDMS, which carries codebase annotations and
is `@AtomicSerial`-aware.

**`PERMISSIONS.LIST` in `blitz-proxy` JAR:**
Create `blitz-proxy/src/main/resources/META-INF/PERMISSIONS.LIST` listing the
permissions the blitz-proxy code declares it needs at the client side. The BAE reads
this file; any blocking `<clinit>` path guarded by a permission listed here will be
upgraded from `BLOCKING_GUARDED` to `BLOCKING_DECLARED` (`DANGEROUS`). Keep the list
minimal — never include `SocketPermission` or `createVirtualThread` without SPIFFE
principal scoping.

---

### 4.6 Denial-of-Service Hardening

The following DoS vectors are present in the current codebase:

#### 4.6.1 Unbounded blocking on `take` / `read`

```java
// BlitzServiceImpl.java — current (no cap)
public MangledEntry take(MangledEntry anEntry, Transaction aTxn, long aWaitTime) {
    stopBarrier();
    return theSpace.take(anEntry, aTxn, aWaitTime); // aWaitTime can be Long.MAX_VALUE
}
```

A client can pass `Long.MAX_VALUE` (or `Lease.FOREVER` as waitTime), tying up a
dispatch thread indefinitely.

**Fix:** Cap `aWaitTime` before delegating:
```java
// In BlitzServiceImpl (or the new AbstractJiniService subclass)
private static final long MAX_BLOCKING_WAIT_MS = 60_000L; // configurable

public MangledEntry take(MangledEntry anEntry, Transaction aTxn, long aWaitTime)
        throws RemoteException, TransactionException {
    readyState.check();
    aWaitTime = Math.min(aWaitTime, MAX_BLOCKING_WAIT_MS);
    // ... delegate to SpaceImpl
}
```

Add a config entry `maxBlockingWaitTime` (milliseconds; default 60 000).

#### 4.6.2 Lease duration — unlimited by default

```java
// blitz.config — current
entryLeaseBound  = 0;   // 0 = unlimited (Lease.FOREVER permitted)
notifyLeaseBound = 0;
```

An unauthenticated client can write entries with `Lease.FOREVER`, filling disk/memory.

**Fix:** Change the secure default to a bounded maximum, e.g.:
```java
entryLeaseBound  = 3600000;  // 1 hour in milliseconds
notifyLeaseBound = 3600000;
```

Operator opt-in for `Lease.FOREVER` should require explicit configuration and should
be paired with SPIFFE principal gating (only trusted workload identities may request
unlimited leases).

#### 4.6.3 Unbounded write queue

`desiredPendingWrites = 256` is a soft target, not a hard limit. A write flood can
cause memory exhaustion or disk exhaustion before back-pressure is applied.

**Fix:**
- Add a `maxPendingWritesHard` config entry (e.g., default 1024).
- Protect the `WriteDaemon` queue with a `Semaphore(maxPendingWritesHard)`.
- When the semaphore cannot be acquired within a short timeout, return a
  `RemoteException` to the caller rather than blocking the dispatch thread.

#### 4.6.4 NIO/MINA transport — unbounded thread pool and work queue

```java
// ServerSessionHandler.java — current
new ThreadPoolExecutor(1, 16, 60, TimeUnit.SECONDS,
    new LinkedBlockingQueue()); // UNBOUNDED work queue
```

A flooded client can enqueue thousands of pending requests.

**Fix:** Replace with a bounded queue and a `RejectedExecutionHandler` that returns an
error to the sender:
```java
new ThreadPoolExecutor(1, 16, 60, TimeUnit.SECONDS,
    new LinkedBlockingQueue(256), // bounded
    new CallerRunsPolicy());       // or throw RejectedExecutionException
```

Alternatively, switch entirely to JGDMS's built-in JERI transport, which has correct
back-pressure semantics and eliminates the separate MINA/NIO code path.

#### 4.6.5 Virtual thread `<clinit>` pinning (JDK 21-23)

When Blitz is migrated to use virtual threads (required for JGDMS JERI compatibility),
any `<clinit>` reachable from a blocking I/O sink can pin a carrier thread on JDK 21-23
(JEP 491 resolves this in JDK 24+, but class-load lock starvation risk remains).

Candidates to audit in Blitz:
- `Disk` (`<clinit>` calls `Logger.getLogger` + static BerkeleyDB config — low risk)
- `WriteDaemon` (`<clinit>` static field init — check for synchronized blocks)
- `EntryReposImpl` (static `HashMap` init — safe)

The BAE's `ClinitBlockingVisitor` will flag any `<clinit>` → blocking-sink path as
`BLOCKING` or `BLOCKING_GUARDED`. If those paths are guarded by a permission declared in
`PERMISSIONS.LIST`, the verdict is upgraded to `BLOCKING_DECLARED` → `DANGEROUS`.

**Fix:** Ensure no Blitz `<clinit>` calls `synchronized` + blocking I/O. Move any such
initialization into instance init or lazy-init patterns.

#### 4.6.6 Deserialization of arbitrary client-supplied objects

`MangledEntry.readObject()` and the NIO `MarshallUtil.unmarshall()` path use raw
`ObjectInputStream` without type filtering. Any class reachable from the JVM classpath
can be instantiated via a crafted serialized stream.

**Fix (primary):** Migrate to `@AtomicSerial` (see §4.5). `@AtomicSerial`'s
`GetArg`-constructor pattern allows field-by-field validation before object construction
is complete, blocking gadget-chain exploitation.

**Fix (secondary):** Replace `java.rmi.MarshalledObject` with `MarshalledInstance`
from JGDMS. `MarshalledInstance` carries codebase annotations and is
`@AtomicSerial`-aware.

#### 4.6.7 Notify listener — no authentication requirement

`RemoteEventDispatcher` calls `notifyPreparer.prepareProxy(listener)` on a received
`RemoteEventListener`. With `BasicProxyPreparer`, any arbitrary proxy is accepted as
a notify target, including unauthenticated or malicious listeners that can absorb
event callbacks and exhaust dispatch threads.

**Fix:** See §4.4 — replace `notifyPreparer` with `VerifyingProxyPreparer` requiring
`Integrity.YES`. Additionally, require that the listener's workload SPIFFE principal
is in the set of trusted principals (enforced by the three-layer policy stack).

#### 4.6.8 `RuntimePermission("createVirtualThread")` scoping

If Blitz is updated to use virtual threads internally, the
`RuntimePermission("createVirtualThread")` grant must be constrained. Per the JGDMS
architecture:

- If this permission appears in `PERMISSIONS.LIST` without a SPIFFE principal scope, the BAE
  flags it as `DANGEROUS`.
- If granted without scoping, a compromised proxy could spawn unbounded virtual threads,
  exhausting the `ForkJoinPool` carrier pool.

**Fix:** Grant `createVirtualThread` only within a policy rule that requires the Blitz
SPIFFE workload principal (`spiffe://example.org/blitz/space`), preventing any other
code (including client proxies) from inheriting the grant.

---

### 4.7 Policy Stack Integration

**Current state:** No policy stack. The service relies on the JVM's default open policy
or whatever `RMISecurityManager` imposes (which is essentially nothing in practice).

**Required deployment configuration:**

#### Layer 1 — SpiffePolicyFile (bootstrap)

Create a Blitz-specific bootstrap policy file, served over HTTPS from an operator-controlled
server. CA-pin the certificate used to serve the file. The policy must be minimal:

```
// bootstrap-blitz.policy
grant principal SpiffePrincipal "spiffe://example.org/blitz/space" {
    // SPIRE socket
    permission java.net.SocketPermission "unix:/run/spire/sockets/agent.sock", "connect";
    // JERI listen
    permission java.net.SocketPermission "localhost:1024-65535", "listen,accept";
    // BerkeleyDB data directory
    permission java.io.FilePermission "/var/lib/blitz/-", "read,write,delete";
    // Logging
    permission java.util.logging.LoggingPermission "control";
};
```

#### Layer 2 — RemotePolicyProvider

Wire Blitz to the `InMemoryPolicyService` djinn-wide policy service. At startup:

1. Use `ServiceDiscoveryManager` to find the `RemotePolicyService` in the lookup djinn.
2. Subscribe for policy updates:
   ```java
   remotePolicyService.registerForPolicyUpdates(listener, Lease.ANY);
   ```
3. On `PolicyUpdateEvent` receipt, pull current grants and replace:
   ```java
   String[] grants = remotePolicyService.getCurrentGrants();
   PermissionGrant[] parsed = DefaultPolicyParser.parse(grants);
   remotePolicyProvider.replace(parsed);
   ```

Use the `PolicyUpdateListener` pattern from `jgdms` `policy-service-dl` module.

#### Layer 3 — DynamicPolicyProvider

Configure as the outermost `Policy` provider on the JVM. Chain all three layers:
```
DynamicPolicyProvider → RemotePolicyProvider → SpiffePolicyFile
```

In the JGDMS service starter configuration:
```java
// start-blitz.config
policy = new DynamicPolicyProvider(
    new RemotePolicyProvider(
        new SpiffePolicyFile("https://policy.example.org/blitz/bootstrap.policy")));
```

#### `GrantPermission` ceiling

In the djinn-wide policy (`RemotePolicyProvider`), declare `GrantPermission` entries
only for the specific permissions Blitz may dynamically grant to client proxies. Never
include `PolicyPermission("Remote")`, `GrantPermission` itself, or `AllPermission` in
delegatable grants.

---

### 4.8 SCAP Pipeline Integration

**Current state:** No integration. Blitz is not registered with the Codebase Downloader
Service, and its proxy JAR is not submitted to the BAE for analysis.

**Required changes:**

1. Ensure the JGDMS `PreferredProxyCodebaseProvider` is on the classpath at the client
   side. It automatically calls `VerdictRegistry.getVerdictByHash()` for each JAR before
   creating a `PreferredClassLoader`. (This is completed JGDMS infrastructure — §12
   item 24 in the reference document is done.)

2. Register the `blitz-proxy` JAR with `CodebaseDownloaderService` so it is proactively
   fetched and analysed by the BAE pool.

3. Add `META-INF/PERMISSIONS.LIST` to `blitz-proxy` (see §4.5).

4. The `blitz-proxy` codebase must be served over HTTPS (not plain HTTP) so that the
   downloader can verify the TLS certificate and prevent substitution attacks.

---

### 4.9 Module System (`module-info.java`)

**Required changes:**

Add `module-info.java` to each Maven module:

```java
// blitz-proxy/src/main/java/module-info.java
module org.dancres.blitz.proxy {
    requires net.jini.core;
    requires net.jini.jeri;
    requires au.zeus.jdk.io;           // @AtomicSerial
    exports org.dancres.blitz.remote;
    exports org.dancres.blitz.mangler;
    exports org.dancres.blitz.lease;
    exports org.dancres.blitz.notify;
    exports org.dancres.blitz.oid;
    // open for JGDMS deserializer
    opens org.dancres.blitz.remote to au.zeus.jdk.io;
    opens org.dancres.blitz.mangler to au.zeus.jdk.io;
}
```

```java
// blitz-service/src/main/java/module-info.java
module org.dancres.blitz.service {
    requires org.dancres.blitz.proxy;
    requires org.dancres.blitz.common;
    requires au.net.zeus.jgdms.service.support;  // AbstractJiniService
    requires net.jini.jeri;
    requires net.jini.lookup;
    requires org.apache.river.thread;             // ReadyState
    requires com.sleepycat.je;
    // ...
}
```

---

## 5. Comparison with JGDMS Outrigger

JGDMS's own `outrigger` service (`TransientOutriggerImpl` → `OutriggerServerWrapper`) is
the closest reference implementation to Blitz and should be used as a code template.

| Feature | Outrigger (JGDMS) | Blitz (current) |
|---|---|---|
| Base class | `AbstractJiniService` | Custom lifecycle |
| Activation | Removed | Present (dead code on JDK 21+) |
| `SecurityManager` | None | `RMISecurityManager` at startup |
| Startup path | `Subject.callAs` / SPIFFE ambient | `Subject.doAsPrivileged` |
| Wire types | `@AtomicSerial` throughout | Raw `Serializable` |
| Proxy preparation | `VerifyingProxyPreparer` | `BasicProxyPreparer` |
| Policy | Three-layer stack | None |
| SPIFFE | Yes | No |
| `ReadyState` | Yes | Custom `stopBarrier()` |
| `com.sun.jini.*` | None | Throughout |

---

## 6. Prioritised Work Plan

| Phase | Items | Dependency | Risk if deferred |
|---|---|---|---|
| **1 — Foundation** | Update Maven deps + coordinates; Java 21 target; remove `com.sun.jini.*`; module-info | None | Nothing else can proceed |
| **2 — Lifecycle** | `AbstractJiniService` migration; remove `RMISecurityManager`; replace `doAsPrivileged`; SPIFFE or JAAS path | Phase 1 | Service won't start on DirtyChai JDK |
| **3 — DoS hardening** | `maxBlockingWaitTime` cap; lease bound defaults; bounded write queue + Semaphore; bounded NIO thread pool | Phase 1 | Live DoS vectors against deployed service |
| **4 — Wire safety** | `@AtomicSerial` migration (108 classes); replace `MarshalledObject` with `MarshalledInstance` | Phase 1 | BAE condemns blitz-proxy; deserialization attacks |
| **5 — Policy stack** | Deploy SpiffePolicyFile; wire RemotePolicyProvider; configure DynamicPolicyProvider; replace BasicProxyPreparer with VerifyingProxyPreparer; add PERMISSIONS.LIST | Phases 1, 2 | No GrantPermission ceiling; policy is open |
| **6 — SCAP pipeline** | Register with CodebaseDownloaderService; VerdictRegistry integration; HTTPS codebase serving | Phase 5, external infra | Clients load blitz-proxy blindly without BAE verdict |

---

## 7. Key Design Decisions

These are decisions that should be made before implementation begins:

| Decision | Options | Recommendation |
|---|---|---|
| Authentication path | SPIFFE (Path A) vs. JAAS `LoginContext` (Path B) | Path A — aligns with JGDMS standard; no JAAS config file maintenance |
| Virtual threads | Use JGDMS JERI virtual-thread dispatch | Yes — required for JGDMS JERI compatibility; audit `<clinit>` first |
| NIO/MINA transport | Keep custom NIO or switch to JGDMS JERI | Switch — eliminates `ServerSessionHandler` thread pool DoS vector; reduces maintenance |
| `entryLeaseBound` default | `0` (unlimited) or bounded (e.g. 1 hour) | Bounded default; unlimited opt-in via config + SPIFFE scoping |
| `Lease.FOREVER` for trusted services | Allow or deny | Allow only for callers with the Blitz SPIFFE workload principal |
| SCAP pipeline | Self-hosted BAE pool or shared djinn BAE | Shared djinn BAE (reuse existing JGDMS infrastructure) |

---

## 8. Files to Create / Modify (summary)

### Create

| File | Purpose |
|---|---|
| `blitz-proxy/src/main/java/module-info.java` | Java module descriptor for proxy |
| `blitz-service/src/main/java/module-info.java` | Java module descriptor for service |
| `blitz-common/src/main/java/module-info.java` | Java module descriptor for common |
| `blitz-proxy/src/main/resources/META-INF/PERMISSIONS.LIST` | BAE permission declaration for client-side proxy |
| `src/main/resources/config/blitz-spiffe.config` | New config for SPIFFE path (no loginContext) |
| `src/main/resources/policy/bootstrap-blitz.policy` | Bootstrap policy for SpiffePolicyFile |

### Modify

| File | Changes |
|---|---|
| `pom.xml` (root) | Java 21 target; JGDMS coordinates; current plugin versions |
| `blitz-service/pom.xml` | Replace `org.apache.river:outrigger` with JGDMS equivalent |
| `BlitzServiceImpl.java` | Replace with `AbstractJiniService` subclass |
| `blitz.config` | `entryLeaseBound`, `notifyLeaseBound`, `maxBlockingWaitTime`; JGDMS exporters |
| `blitz.ssl.config` | SPIFFE constraints; remove JAAS `loginContext` |
| All 108 `Serializable` classes | Add `@AtomicSerial`; `(GetArg)` constructor; `serialize(PutArg, T)` method |
| `ServerSessionHandler.java` | Bounded `ThreadPoolExecutor` work queue |
| `WriteDaemon.java` (or caller) | `Semaphore` on pending write count |
| `BlitzServiceImpl.take/read` | `maxBlockingWaitTime` cap |

---

## 9. References

| Document | Location |
|---|---|
| AI Agent Context v19 | `pfirmstone/JGDMS:JGDMS/docs/Big picture security architecture/AI_Agent_JGDMS-GrantPermission-RoleManagement-context_8.md` |
| JGDMS-STD-001 | AtomicSerial compliance rules (in JGDMS repo docs) |
| JGDMS-STD-002 | Five-host SCAP pipeline (in JGDMS repo docs) |
| JGDMS-STD-003 v3.1 | Multi-Subject Identity Architecture (in JGDMS repo docs) |
| `AbstractJiniService.java` | `pfirmstone/JGDMS:JGDMS/services/jgdms-service-support/src/main/java/au/net/zeus/jgdms/service/support/AbstractJiniService.java` |
| `TransientOutriggerImpl.java` | `pfirmstone/JGDMS:JGDMS/services/outrigger/outrigger-service/src/main/java/com/sun/jini/outrigger/TransientOutriggerImpl.java` |
| `InMemoryPolicyServiceImpl.java` | `pfirmstone/JGDMS:JGDMS/services/policy-service/…` |
| `PolicyUpdateListener.java` | `pfirmstone/JGDMS:JGDMS/policy-service-dl/…` |
| `PreferredProxyCodebaseProvider.java` | `pfirmstone/JGDMS:JGDMS/jgdms-pref-class-loader/…` |
