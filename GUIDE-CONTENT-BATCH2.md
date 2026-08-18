# Guide content — Batch 2 additions

Appended with the same status as prior GUIDE-CONTENT files: spec, implement
verbatim, propose changes rather than edit. The two-register rule from the
original document governs all prose here.

Two pages, each serving two rules, anchored per-rule sections — same
mechanism as Batch 1's loss page.

---

## Guide page: Connecting — and failing to connect
### (serves R02 · R03)

### One-line summary
Before any data moves, two computers have to agree to talk. These two checks
look at attempts that never got that far — either nobody answered, or
somebody said no.

### What this usually means — the shared picture
Every TCP connection starts the same way: one side sends an opening request,
the other side either accepts it, refuses it, or says nothing at all. Silence
and refusal look similar from a distance — "I couldn't connect" — but they
mean different things and point at different places to look.

---

### <a name="r02"></a>Nobody answered — R02

**What it is.** The connecting side sent its opening request, more than
once, following the standard pattern of trying again after longer and longer
waits. Nothing came back — not an acceptance, not a refusal, nothing.

**What it usually means.** The request never reached anything capable of
responding. Typically a firewall or security rule silently discarding it, a
service that isn't listening on that address or interface, or a route that
doesn't lead where it's supposed to. A refusal (see R03) at least proves
something was reachable; silence usually means it wasn't.

**What it can't tell you.** Whether the block happened close to the sender,
close to the destination, or somewhere in between — a capture at one point
sees only that nothing came back, not where the request stopped. It also
can't rule out an asymmetric path: the reply may exist and simply be
travelling a route this capture point never sees.

---

### <a name="r03"></a>Connection refused — R03

**What it is.** The connecting side's opening request was met with an
explicit refusal rather than silence or acceptance. Something was there,
running, and reachable — it just said no.

**What it usually means.** Most often, nothing is listening on the port
that was asked for: the service isn't running, isn't started yet, or is
listening somewhere else. This is usually the easiest of these findings to
resolve, because the application on that host will typically have already
reported the same thing in its own error message.

**What it can't tell you.** Whether the refusal genuinely came from the
destination or from something in between impersonating it — occasionally a
device on the path manufactures a refusal on a host's behalf. When the
refusal's own signature looks inconsistent with the rest of that host's
traffic, the finding notes it; otherwise, it's reasonable to take the
refusal at face value.

---

### The pattern in a capture — reading these together
If an application already reported "connection refused" before you opened a
capture, R03 is usually confirming what you already knew, in more precise
language. Its main value is corroboration and timing rather than new
information. R02 tends to be the more useful of the two, because "nothing
came back at all" is often not obvious from the application's own error
message, and points somewhere different: at what's between the two hosts,
not at the destination itself.

### What to check next, in more depth
- For no response at all: firewall and security-group rules along the path,
  whether the destination is listening on the expected interface, and
  whether a route to it exists at all from the connecting side.
- For an explicit refusal: whether the intended service is running and bound
  to the right address and port on that host. If the application already
  told you this, the capture is mainly useful for pinning down exactly when
  it happened and how many attempts were made.

---

## Guide page: Connections that end early, or too often
### (serves R09 · R14)

### One-line summary
These two checks look at connections after they were successfully
established: ones that were cut off abruptly while still carrying data, and
ones that opened and closed over and over in a way that looks like overhead
rather than normal use.

### What this usually means — the shared picture
A connection can end two ways: a clean close, where both sides agree they're
done, or an abrupt one, where it's simply terminated. And a connection can be
used two ways: held open for a while and reused, or opened fresh for every
single exchange. Both checks below are about connections that are working —
data is moving — but the way they start or end suggests something worth a
second look.

---

### <a name="r09"></a>Cut off mid-transfer — R09

**What it is.** A connection ended abruptly — not with the normal two-way
"we're both done" close — while data was still actively moving across it, or
very shortly after.

**What it usually means.** Several possibilities, and the capture alone
usually can't distinguish them: the application on one end deliberately
aborted the connection (a legitimate way to close quickly, without waiting
for a graceful handshake), something on that host hit a limit and cut the
connection, or a device on the path terminated the session. When many
connections are cut this way at a similar point in their life, and none of
the tool's other checks explain it, that consistency is itself a clue —
it suggests a pattern rather than isolated failures.

**What it can't tell you.** Why the termination happened. An abrupt close
from an application working as designed and an abrupt close from something
going wrong produce an identical signature on the wire — the same reset,
sent at a similar moment. The application's own logs at that timestamp are
usually the fastest way to tell the two apart.

---

### <a name="r14"></a>Rapid connection cycling — R14

**What it is.** The same client opened and closed a large number of
connections to the same destination in a short time, each one lasting only
briefly.

**What it usually means.** Most often, connections aren't being reused when
they could be. Establishing a connection has a fixed cost — the initial
back-and-forth to agree to talk — and paying that cost on every single
exchange, instead of holding one connection open and reusing it, adds
overhead that is small per-connection but adds up at volume. This is
frequently a configuration matter: a connection pool set too small, timeouts
closing connections sooner than the application expects to reuse them, or
software simply not written to reuse connections at all.

**What it can't tell you.** Whether the overhead actually matters for this
use case. Rapid cycling that adds a few milliseconds per exchange may be
completely fine for a low-volume, infrequent task, and only becomes worth
fixing when the rate is high enough for the added overhead to accumulate
into something noticeable.

### The pattern in a capture — reading these together
Both checks describe connections doing something other than settle into a
long, quiet, reused pattern. An R09 finding is about how a connection ended;
an R14 finding is about how many connections there were in the first place.
It's possible to see both on the same pair of hosts — many short connections,
several of which also happened to end abruptly — and when that happens, the
churn (R14) is usually the more fundamental thing to address, since fixing
connection reuse often reduces the number of endings there are to worry
about.

### What to check next, in more depth
- For abrupt endings: the application's own logs at the exact moments listed
  in the finding — deliberate aborts, resource limits, and crashes all leave
  different traces there that the capture alone can't distinguish.
- For rapid cycling: the client's connection-pooling or keep-alive
  configuration, and whether anything — a proxy, a load balancer, a firewall
  session timeout — is closing connections sooner than the client expects
  to be able to reuse them.
