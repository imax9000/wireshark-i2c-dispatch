# Wireshark plugin for matching protocols by I2C address

By default, I2C dissector allows specifying only one protocol for parsing
payloads. This is not sufficient, for example, when you have multiple different
devices on the bus.

This plugin adds another layer of indirection, allowing to match protocols to
I2C addresses the same way as with TCP/UDP ports.

To enable it after installing, open "Decode As..." dialog and set
"I2C message dissector" to be decoded as "I2C address". Now you can add your
own dissectors to "i2c.addr" table, and they will be used automatically.

## Installing

1. Install CMake and `wireshark-dev` package or somesuch.
2. `mkdir build && cd build && cmake .. && make install`.

It will be compiled for your version of Wireshark and installed into appropriate
location under `~/.local`.

## Q&A

### Why match by address?

Most chips that have I2C interface have fixed addresses (sometimes they can be
tweaked in a small range), so writing your dissector to apply to one or a few
addresses by default will be good enough™ 95% of the time.

### Shouldn't something like this be available out-of-the-box?

Yes, probably. I may end up sending a patch upstream, but I'm definitely not in
the mood to get it also backported to an ancient Wireshark release that comes
from a distro I happen to use, nor bother to install a newer version some other
way.

### Why I don't see my existing I2C dissectors in the dropdown?

Those use a different dissector table, "i2c.message". I did try to make some use
of it, but the UI got confused and it didn't really work.

If you know how to do that properly - please send me a PR.
