# Guide content — Batch 1 additions

Appended to the guide with the same status as the existing GUIDE-CONTENT.md:
spec, implement verbatim, propose changes rather than edit. The two-register
rule from the original document governs all prose here.

Structural note for implementation: the loss page below is ONE page serving
FOUR rules (R05, R06, R07, R08). Each rule's section carries an anchor;
arriving from a finding lands on that rule's section with the context block at
top, arriving from the index lands at the page top. The bijection test must be
updated to permit this many-to-one mapping — see the session brief.

---

## Guide page: Packet loss, retransmission, and reordering
### (serves R05 · R06 · R07 · R08)

### One-line summary
When data goes missing in transit, TCP notices and resends it. These four
checks look at how often that happened, how it happened, and — just as
important — when something merely *looked* like loss but wasn't.

### What this usually means — the shared picture
Networks are allowed to lose packets; TCP is built to recover. The question a
capture can answer is never "was anything lost" — on a busy network the answer
is almost always yes — but "how much, in which way, and did it cost real
time." A small amount of quickly-recovered loss is ordinary background. Loss
that stalls transfers, or loss flowing in only one direction, is a pattern
worth following.

The four sections below are four ways the same story can go.

---

### <a name="r06"></a>Quick recovery (fast retransmit) — R06

**What it is.** When a packet goes missing mid-stream, the receiver keeps
acknowledging the last data it got in order. The sender hears the same
acknowledgement several times, concludes something was lost, and resends it
without waiting. Recovery typically costs one round trip — often just
milliseconds.

**What it usually means.** A small rate of this is a healthy network doing
normal work; the internet loses packets by design. This check reports it when
the rate on one path stands out against the rest of the capture, because a
path losing noticeably more than its neighbours usually has something
congested or faulty along it.

**What it can't tell you.** Where along the path the loss happened. A capture
taken at one point sees that a packet never arrived, not which hop dropped it.

---

### <a name="r05"></a>Stalled recovery (timeout retransmission) — R05

**What it is.** Sometimes the sender gets no acknowledgements at all — not
even the repeated ones that trigger quick recovery. Its only option is to
wait for a timer to expire and try again, and the timer doubles after each
failure. Each of these timeouts costs hundreds of milliseconds to seconds of
pure waiting.

**What it usually means.** Loss severe enough that even the recovery traffic
is being lost, or a path that has briefly gone completely silent. This is the
disruptive kind of loss: the connection isn't recovering gracefully, it is
stopping and hoping. When this check fires, the time lost is usually
noticeable to whoever was waiting on the transfer.

**What it can't tell you.** Whether the silence was loss or something
swallowing the connection whole — a failing link and a device silently
discarding the session can look identical from one end. The pattern of what
came before, and whether other connections on the same path suffered too, is
the next thing to look at.

---

### <a name="r07"></a>Looks like loss, isn't (reordering) — R07

**What it is.** Sometimes packets arrive out of order — a later packet takes
a faster lane and overtakes an earlier one. To a casual reading this looks
exactly like loss followed by resending. It isn't: nothing was lost and
nothing was resent. This check identifies that pattern and *removes* it from
the loss counts, which is why it exists — without it, the other checks here
would blame the network for losing data that arrived fine.

**What it usually means.** Traffic taking multiple paths through the network,
or features on the capturing machine's own network card that batch and
release packets. It is usually a configuration fact rather than a fault,
though heavy reordering can slow TCP down on its own.

**What it can't tell you.** Which of those causes it is. And on IPv6 one of
its supporting signals doesn't exist, so its confidence is lower there — the
finding says so when that applies.

---

### <a name="r08"></a>Loss in one direction only — R08

**What it is.** Every connection is two streams, one in each direction. This
check compares loss in the two directions of the same connection, and speaks
up when one direction is losing heavily while the other is nearly clean.

**What it usually means.** Something specific to one direction of travel: a
congested uplink, traffic shaping applied one way, or the two directions
taking different routes entirely. Loss caused by a shared problem — a bad
cable, an overloaded switch — tends to hit both directions; loss in one
direction points at something on that side's path.

**What it can't tell you.** It needs both directions present in the capture
to say anything. Captures taken from a mirror port configured one-way can't
support this comparison, and the tool says so rather than guessing.

---

### The pattern in a capture — reading these together
The four findings are meant to be read as one picture. Heavy quick-recovery
with no timeouts: a lossy but functioning path. Timeouts clustered on one
connection while its neighbours are clean: something specific to that
conversation. Reordering findings appearing where you expected loss: the
"loss" was never real. A one-direction finding on top of any of these: the
place to look is on that direction's path.

The finding cards show which frames to open, and the amounts are always
compared against the rest of the same capture, so "a lot" means "a lot for
this network at this moment", not a textbook number.

### What to check next, in more depth
- If quick-recovery loss stands out on one path: the links along that path —
  interface error counters and utilisation on the switches and routers
  between the two hosts are where per-hop truth lives; the capture cannot
  provide it.
- If timeout stalls appear: whether the path went fully silent (check the
  frames just before the stall — was *anything* acknowledged?) and whether
  other connections between the same hosts stalled at the same moment.
- If reordering is reported: the capture location. Reordering measured on an
  endpoint often reflects the endpoint's own network card settings rather
  than the network; a capture taken on a tap or mirror port would separate
  the two.
- If loss is one-directional: that direction's route and any rate limiting or
  shaping applied to it. Comparing traceroutes in each direction is a quick
  first look at whether the paths even match.

---

## Guide page: Capture quality — R15

### One-line summary
Before trusting what a capture says about the network, it's worth knowing
what the capture itself failed to see. This check examines the capture file
rather than the traffic in it.

### What this usually means
A capture is a recording, and recordings have blind spots: they start late
and miss the beginning of conversations, they clip packets to save space,
they get taken on machines that batch packets in misleading ways, and — the
quiet one — the recording machine itself can drop packets when it can't keep
up, manufacturing "loss" that never happened on the wire.

None of these make a capture worthless. They make specific *questions*
unanswerable, and this check's job is to say which ones, so the other
findings can be read with the right amount of trust. Its results appear in
the banner at the top of every report rather than as findings, because they
qualify everything below them.

### What the individual notices mean
- **"Headers declare a length no sender could have written."** Something
  between the sending machine and this file altered the packet headers. This
  is the one notice that isn't about a blind spot: the recording isn't
  incomplete, it's wrong. Findings in the same report were read out of those
  headers, so they describe the file rather than the network, and shouldn't
  be acted on without a second capture to compare against. Clipping doesn't
  cause this — a clipped packet is short, and its headers still say what the
  sender wrote.
- **"Flows began before the capture started."** The recording missed those
  conversations' opening handshakes, where the two sides state how they'll
  measure available space. Without that, questions about window sizing can't
  be answered for those flows — though stalls where a receiver stopped
  accepting data entirely remain fully visible.
- **"Packets were clipped" (snaplen).** The capture kept only the first part
  of each packet. Headers usually survive; anything needing the full packet
  doesn't.
- **"The capture host dropped packets."** The recording machine couldn't keep
  up and discarded some packets before writing them. Dropped-by-the-recorder
  and lost-on-the-network look identical afterwards, so when this notice
  appears, loss findings in the same report are marked as less certain.
- **"Oversized packets suggest capture on an endpoint."** The machine doing
  the capturing was assembling packets in batches before the recorder saw
  them. Sizes and some timing details reflect that batching, not the wire.
- **"Flows captured in one direction only."** Half of each conversation is
  missing — comparisons between the directions can't be made.

### What it doesn't mean, and what this check can't tell you
- A notice is not a fault in your network. Every one of them is about the
  recording, not the traffic.
- It can't recover what wasn't recorded. It can only mark the boundary
  between what this file can and cannot support.
- A clean bill from this check doesn't make the capture complete — it means
  none of the *detectable* recording problems were present.

### What to check next, in more depth
Most capture-quality problems have the same fix: take the capture again,
better, if the fault is reproducible. Concretely — start the capture before
reproducing the problem, capture full packets rather than clipped ones, use
the pcapng format so the recorder's own drops are recorded, prefer a network
tap or mirror port over capturing on a busy endpoint, and if the recorder
was dropping packets, give it a bigger buffer or a quieter machine. The
in-app notices say which of these applies to your file.
