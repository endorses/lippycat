# Packet-stream recording

The VHS tape records ten seconds of synthetic packets flowing through the live
packet view with details enabled and the newest packet selected. Startup and
shutdown are hidden. It exports `packet-stream.gif` and a matching
`packet-stream.png` in this directory. Run every command from the repository root.

Install [VHS](https://github.com/charmbracelet/vhs), `ttyd`, and FFmpeg so their
commands are available on your `PATH`.
The recording uses a wide terminal, Solarized Dark, and 15 frames per second.
The included application configuration keeps personal filters and settings out
of the demo.

## Prepare capture permissions

VHS runs as your normal user. Give a separate copy of lippycat the network
capabilities so its virtual terminal can capture without a sudo prompt:

```bash
mkdir -p bin
cp ./lc ./bin/lc-demo
sudo setcap cap_net_raw,cap_net_admin=ep ./bin/lc-demo
getcap ./bin/lc-demo
```

The original binary is unchanged. Copying a rebuilt binary over `lc-demo`
requires applying the capabilities again.

## Run the demo

In one terminal, start paced, continuous replay of the existing synthetic PCAP:

```bash
sudo ./lc sniff -r testdata/pcaps/demo-mixed.pcap -V \
  --vif-replay-timing --replay-loop 0 --quiet
```

In a second terminal, record the live capture:

```bash
vhs docs/demos/packet-stream.tape
```

The tape enables details with `d`, focuses the packet list with `Escape`, and
follows the newest packet with `G`. It records only the TUI, then saves a still
frame and quits. Keep replay running until recording finishes, then stop replay
with Ctrl+C and remove the temporary capability-bearing binary:

```bash
rm ./bin/lc-demo
```

Preview the GIF and PNG before embedding either asset in the README or manual.
The tape is syntax-validated, and the rendered GIF has been checked with live
synthetic replay and embedded in the README and manual introduction. Re-recording
requires the capture-capability setup above. The tape does not start replay or
grant privileges automatically.

## Validate the tape

```bash
vhs validate docs/demos/packet-stream.tape
```

Validation parses the tape without capturing traffic or launching the TUI.
