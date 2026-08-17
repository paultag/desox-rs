# `src/replay`

In `src/replay` lives the "replay tests". This works by me interacting
with a physical card, recording the APDU traffic, and writing that traffic
(hex encoded) to the repo.

The source that generated the traffic is in the coresponding test case.
That traffic is loaded into a "MockBackend", which asserts the input APDU
is byte-identical to the one it has, and replies with the expected response.

## Development

To generate the replay file, the DESFire card needs to be formatted (I have
a little program locally that just authenticates and calls "format"), and
run the test case (one-by-one) with something like:

```sh
$ desfire format  # or however you format your cards
$ RUSTFLAGS="--cfg desox_replay_rw" cargo test \
  --features pcsc \
  replay::file_io
```

Doing this will generate a new file, since the session key will change (even
though we hardcode rnd_a -- the card will pick a new rnd_b!), which means
all CMAC signature(s) or encrypted data message(s) will chnage.
