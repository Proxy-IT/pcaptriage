# Guide content — Batch 3 additions

Same spec status as prior GUIDE-CONTENT files: implement verbatim, propose
changes rather than edit. The two-register rule from the original document
governs this prose.

Two pages, each serving two rules, anchored per-rule sections — same
mechanism as Batch 1 and 2.

**Grouping rationale** (stated so it can be vetoed): R10 and R13 are both
about the path between two hosts — how long it takes, and what size it will
carry. R11 and R12 are both about services a connection depends on before it
can do useful work. That split keeps each page answering one question.

---

## Guide page: The path between two hosts
### (serves R10 · R13)

### One-line summary
These two checks look at the route packets take rather than at the machines
at either end: how long the round trip takes, and whether the path will
carry the packet sizes being sent.

### What this usually means — the shared picture
Two computers can both be healthy and still communicate badly, because
something between them is slow, long, or unable to carry what they're
sending. Neither of these checks is about an application. Both are about the
distance and the pipe.

---

### <a name="r10"></a>Longer round trips than everything else — R10

**What it is.** The time for a packet to reach a host and be acknowledged,
compared against the same measurement for every other host in the capture.
This check speaks up when one host or one group of hosts sits far above the
rest.

**What it usually means.** Distance, most often — a host that is physically
much further away, or reached over a link with more hops. Congestion is the
other common cause, and the two look different: distance produces latency
that is high but steady, while congestion produces latency that varies. The
finding reports which pattern it saw, because that distinction is usually
the fastest way to narrow the cause.

Elevated round-trip time is not a fault on its own. It becomes a problem
when something above it is sensitive to it — a chatty protocol making many
small round trips, for instance, where every exchange pays the cost again.

**What it can't tell you.** Where along the path the time is being spent.
The capture sees only the total. It also can't tell you whether the latency
is acceptable: 200ms is unremarkable to a host on another continent and
alarming inside a datacentre, and the check has no idea which situation it
is looking at. It compares against the other hosts in the same capture, so
if everything in the file is far away, nothing will stand out.

---

### <a name="r13"></a>Large packets vanish, small ones don't — R13

**What it is.** Every link has a maximum packet size it will carry. When
something along a path has a smaller limit than the sender expects, large
packets are dropped and small ones get through. This check looks for that
signature: repeated retransmissions of large packets on a connection where
smaller packets are being delivered normally.

**What it usually means.** A size limit somewhere on the path — very often a
tunnel or VPN segment, which adds its own overhead and leaves less room for
the data inside. Normally the network reports this back to the sender so it
can adjust. When those reports are blocked, which is common, nothing tells
the sender anything and the connection simply hangs whenever it tries to
send something large.

This produces one of the more confusing symptoms in networking: the
connection works, small exchanges succeed, and transfers stall partway
through for no visible reason. The check reports whether it saw the
size-limit messages or only the silent pattern, because their absence is
itself informative.

**What it can't tell you.** Which device on the path has the smaller limit.
It also can't distinguish a size limit from other causes of large-packet
loss with certainty — it reports a pattern consistent with a size limit,
which is why the next step is testing the path rather than acting on the
finding directly.

---

### The pattern in a capture — reading these together
These two rarely appear together and mean different things when they do.
High round-trip time with everything else healthy is usually a fact about
where a host is, not a fault. Large packets failing while small ones succeed
is a fault almost every time — connections that work for small things and
hang for large ones are not working.

### What to check next, in more depth
- **For elevated round trips:** where the host actually is, and what the path
  to it looks like. A traceroute comparing it against a host the capture
  showed as normal usually explains it in one step. If the latency varies
  rather than staying steady, look for congestion on a shared link instead.
- **For large packets failing:** the maximum packet size along the path,
  paying particular attention to any tunnel or VPN. Testing with
  progressively larger packets will find the threshold. If the network's
  own size-limit messages are being blocked, unblocking them is worth doing
  independently of this connection — they exist to prevent exactly this
  symptom.

---

## Guide page: Services a connection depends on
### (serves R11 · R12)

### One-line summary
Before an application can exchange data, two things usually have to happen
first: a name has to be turned into an address, and an encrypted connection
has to be negotiated. These two checks look at whether those steps worked.

### What this usually means — the shared picture
Both of these are steps that happen before the real work starts, and both
are easy to overlook when something is slow, because the application
reporting the problem is often not the thing that failed. A slow name
lookup and a slow encrypted setup both present to a user as "the
application is slow", and neither is the application's fault.

---

### <a name="r11"></a>Name lookups failing or slow — R11

**What it is.** Turning a name into an address is the first step of most
connections. This check looks at those lookups: ones that got no answer,
ones that came back as errors, and ones that took a long time.

**What it usually means.** A resolver that is unreachable, overloaded, or
returning errors for names it should know. Because a lookup happens before
the connection it enables, a slow one delays everything behind it — and
because the delay lands before any application traffic, it is very
frequently blamed on the application instead.

This check is weighted highly for its size because it explains a
disproportionate number of "everything is slow" reports, and because it is
almost never where an inexperienced reader looks first.

**What it can't tell you.** Why the resolver behaved that way. It also
can't see encrypted lookups at all: when name resolution is carried over an
encrypted channel, this check has nothing to read and says so rather than
reporting that everything was fine.

---

### <a name="r12"></a>Encrypted connections failing to establish — R12

**What it is.** Before encrypted traffic can flow, both sides negotiate:
they agree on how to encrypt, and the server presents a certificate proving
it is who it claims. This check looks at negotiations that failed, that took
an unusually long time, and — where visible — at certificates that are close
to expiring or already expired.

**What it usually means.** A failed negotiation usually means the two sides
couldn't agree on terms, or the client refused the certificate it was shown.
Common causes are a certificate that has expired, one issued for a different
name, or a client and server with no shared encryption method — often after
one side is upgraded and drops support for something older.

Slowness here is different from failure and worth separating: a negotiation
that succeeds but takes a long time usually points at the server being busy
during setup, not at anything wrong with the encryption itself.

**What it can't tell you.** Modern versions of the protocol encrypt most of
the negotiation, so certificate details are frequently not visible in a
capture at all. When that's the case, this check reports what it could see
and states plainly what it couldn't — it does not guess, and an absence of
certificate findings is not a statement that the certificates are fine.

---

### The pattern in a capture — reading these together
Both checks describe delays and failures that happen before an application
sends anything. If either appears alongside a finding about a slow server,
read these first: a connection that spent two seconds resolving a name and
another second negotiating encryption was slow before the server was
involved at all.

### What to check next, in more depth
- **For name lookups:** the resolver's own health and reachability, and
  whether the affected names resolve correctly when queried directly. The
  finding lists the names and times, which usually narrows this quickly.
- **For encrypted connections:** certificate validity and expiry dates
  first, since they are the most common cause and the easiest to check.
  Then whether the client and server still share a supported encryption
  method — mismatches often appear after an upgrade on either side.
