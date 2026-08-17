# Guide content — R01 and R04

Authored content for the in-app guide. This prose is specification in the same
sense as RULES.md's finding wording: implement it as written, flag proposed
changes rather than silently editing. Structure is part of the spec — every
guide page follows this same skeleton, in this order.

## The two registers — rule for all guide content

Finding cards state observations about *this capture* and never make causal
claims. Guide pages teach *patterns in general* and may say what something
usually means, because they describe the pattern, not the user's capture. The
words "usually", "typically", "often" are load-bearing in guide prose — they
are what keeps general teaching from becoming a specific verdict. Guide text
must never assert what is happening in the reader's capture; that remains the
card's job, and the card doesn't do it either.

A test should ban verdict phrasing about the reader's own capture from guide
pages: "your server is", "your network is", "this means your" and similar.

---

## Guide page: R01 — Receiver stopped accepting data (zero window)

### One-line summary
The receiving side of a connection told the sender to stop transmitting,
because it had no room to accept more data.

### What this usually means
Computers receiving data hold it briefly in a buffer until the receiving
application reads it. When the application reads slower than data arrives, the
buffer fills up. When it is completely full, the receiver announces a "zero
window", which is TCP's way of saying: stop sending, I have nowhere to put it.

The sender then waits. It is not broken and the network is not losing anything.
Everything is simply stopped until the receiver frees up room.

This is usually a sign that the receiving machine's application is not keeping
up. Common reasons include the application being busy on CPU, waiting on a disk
or a database, stuck on a lock, or simply overloaded. The pattern typically
points at the receiving host, not at the network between the two machines.

### What it doesn't mean, and what this check can't tell you
- It can't say *why* the application isn't keeping up. CPU, disk, a slow
  downstream dependency, and a stuck thread all look identical from the
  network's point of view. The capture shows the symptom; the cause lives on
  the receiving host.
- Brief zero windows are normal. Buffers fill and drain all the time, and a
  zero window lasting a few milliseconds is routine housekeeping. This check
  only reports when the stall is long enough to matter, and it reports the
  time lost rather than the count, because six harmless blips matter less than
  one four-second stall.
- Occasionally an application slows its reading deliberately as a way of
  pacing the sender. Rare, but it means a zero window is not automatically a
  fault.

### The pattern in a capture
A healthy exchange shows the receiver acknowledging data with a window value
that stays comfortably above zero. In this pattern, you'll see the window
value shrink as the buffer fills, hit zero, and then a gap: the sender goes
quiet because it has been told to. Eventually a "window update" arrives —
the receiver announcing it has room again — and the transfer resumes. The
time between the zero and the update is the stall, and that time is what this
check measures and adds up.

### What to check next, in more depth
Start on the receiving host, at the moment of the stall:
- Was the application busy? CPU, load, and garbage-collection pauses at that
  timestamp.
- Was it waiting on something else? A database query, a downstream API call,
  a disk that was briefly saturated. The application's own logs at the stall
  time are often the fastest answer.
- Is this one connection or many? If several connections to the same host
  stalled together, the host was struggling. One connection alone can be one
  slow request.
Correlating the stall timestamps in the finding against that host's logs and
metrics is usually the shortest path to the cause.

---

## Guide page: R04 — One server much slower to respond than its peers

### One-line summary
One server took much longer to start answering requests than the other
servers in the same capture, and the delay was on the server, not the network.

### What this usually means
When a client asks a server for something, the total wait has two parts: the
time the request and response spend travelling the network, and the time the
server spends working before it starts to answer. This check separates the
two. It measures the travel time on its own, subtracts it, and what remains
is time spent on the server itself.

When one server's remaining time is far larger than every comparable server
in the same capture, the slowness usually lives on that server: the
application working slowly, or waiting on something behind it, like a
database, another service, or storage.

This is the check that answers the most common argument a capture gets pulled
into: is it the network, or is it the application? When this finding appears,
the measured answer is that the network path looked ordinary and the wait
happened after the request arrived.

### What it doesn't mean, and what this check can't tell you
- It can't see inside the server. Slow code, a slow database behind the
  server, a full connection pool, and an overloaded disk all look the same
  from outside: a long pause before the first byte of the answer.
- It can't judge against your expectations. The comparison is against the
  other servers in the same capture, not against what the server is supposed
  to do. A server that is slower than its peers but within its own normal
  range will still be flagged as the outlier it is.
- Encrypted traffic hides what was asked. The check sees that a request went
  in and when the answer started, but not what the request was. A server that
  looks slow may have been given genuinely harder work than its peers.
- Some traffic patterns can't be measured this way. Connections where the
  server pushes data without being asked, or where the client holds a request
  open on purpose, don't fit the question-and-answer shape this check needs,
  and it skips them rather than guessing.

### The pattern in a capture
The request goes in — the last packet of the client's question. Then a wait.
Then the first packet of the server's answer. That gap, minus the network's
round-trip time, is the server's thinking time. Healthy servers in a capture
typically answer in tens of milliseconds; the finding shows the flagged
server's typical and worst times next to the group it was compared against,
so the size of the difference is visible rather than asserted.

### What to check next, in more depth
Start on the flagged server, using the timestamps in the finding:
- The application's own request logs. Most server software records how long
  each request took; the slow ones will stand out at the matching times.
- What the server was waiting on. If the application was fast in its own
  logs but the capture shows a long pause, the wait may be in front of it —
  a full worker pool or a connection queue.
- The dependencies behind it. A slow database or upstream API makes a
  healthy application look slow from the outside. Their logs at the same
  timestamps are the next hop.
- Whether the slowness is constant or spiky. Consistently slow suggests
  capacity or configuration; occasional spikes suggest contention, garbage
  collection, or one expensive kind of request.
