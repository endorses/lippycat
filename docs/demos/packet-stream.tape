# Run from the repository root, with paced replay already running on lc0.
# See README.md in this directory for the capture-capability setup.
Output docs/demos/packet-stream.gif
Set Shell bash
Set Width 1800
Set Height 900
Set FontSize 16
Set Framerate 15
Set Theme "Builtin Solarized Dark"
Set TypingSpeed 0
Require ./bin/lc-demo

Hide
Type "./bin/lc-demo --config docs/demos/config.yaml watch live -i lc0"
Enter
Wait+Screen /CAPTURING/
Sleep 2s
Type "d"
Escape
Type "G"
Sleep 1s
Show
Sleep 10s
Screenshot docs/demos/packet-stream.png
Hide
Type "q"
Sleep 1s
