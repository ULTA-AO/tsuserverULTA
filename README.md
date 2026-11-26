# tsuserverULTA

My little love letter to the ULTA and AO community.

Server for [ULTA AO2](https://github.com/ULTA-AO/ulta-client), the Attorney Online client for the ULTA community. It is based on [tsuserverCC](https://github.com/RealKaiser/tsuserverCC) by RealKaiser and the Case Cafe staff, a fork of [AttorneyOnline/tsuserver3](https://github.com/AttorneyOnline/tsuserver3).

It only accepts the ULTA client (when `ulta_required` is on), and everything from tsuserverCC still works.

### What's new

* Trio pairing: a second partner on screen, with front, behind or middle order.
* Custom text colors per player.
* Narrator mode, with scene tools for fades and menu overlays.
* Character fade in and out.
* Flashback looks in sepia or black and white.
* The server remembers the scene, so someone who joins mid-scene sees what everyone else sees.
* Version checks: clients report their version when they connect, and the server can ask them to update.

### ULTA settings

All of these are in `config_sample/config.yaml`.

* `ulta_required`: disconnect clients that don't announce the ULTA handshake. Off by default.
* `ulta_handshake_timeout`: seconds to wait for the handshake.
* `ulta_required_message`: shown to clients that aren't ULTA clients.
* `ulta_min_version`: oldest ULTA client protocol version that may join.
* `ulta_min_client_version`: oldest ULTA client version (for example `1.0.2`) that may join. Empty means no minimum. Use it to require an update when the protocol did not change.
* `ulta_update_message`: shown to clients that are too old.
* `ulta_custom_colors`: relay players' custom text colors.
* `ulta_narrator`: allow narrator mode.
* `ulta_char_fade`: allow character fades.
* `ulta_scene_tools`: where scene tools work (`off`, `rooms`, `hubs` or `everywhere`).
* `ulta_cm_only`: only CMs and mods can use narrator mode, scene fades and flashbacks. On by default.

### Credits

tsuserverCC by RealKaiser and the Case Cafe staff, tsuserver3 by the Attorney Online developers.

### What's different from tsuserverCC

These commands behave differently here. Anything not listed works as in tsuserverCC.

* `/help`, `/about`, `/helpfiles`: show ULTA information and links.
* `/narrator`: This was actually removed! Narration is done with the Nr button in the ULTA AO client.
* `/timer`: short forms for timer 1. `/timer 50s`, `/timer 1.25m` or `/timer 800m` sets timer 1 and starts it. `/timer +30s` and `/timer -1m` adjust it, and `/timer start`, `pause` and `hide` control it. The explicit `/timer <id> ...` forms still work. A time needs a unit (`s`, `m`, `h`) or the form `1:30`. `+30s` now adds to the time (before, it replaced it).
* `/clearscene`: A CM or mod ends a blackout, whiteout, flashback or faded-out characters in the area for everyone.
* `/ulta`: Shows the ULTA protocol version the server needs, your client's version, and where to download or update.
* `/ultaversions`: mods only. Lists every connected player with their protocol and client version.
* Narrator mode, scene fades and flashbacks can only be used by the area's CM (or the hub's CM) and logged-in mods. Set `ulta_cm_only: false` in the config to let everyone use them.

## AI (Artificial Intelligence) Disclaimer

Since AI is a very convoluted topic right now in the coding hemisphere, I will attach this brief memo to be transparent. I did not rely on AI to code nor to explicitly write mass waves of data. AI was only used in one of two ways: (1) to help me learn some complex topics that my prior coding experience did not teach me, or (2) to fix extremely small (e.g. complicated handshake problems between server and client) issues that otherwise would've taken me ages to resolve on my own.

## Setup

* Python 3.7 or newer.
* Install the dependencies: `python -m pip install --user -r requirements.txt`
* Copy `config_sample` to `config` and edit the values. Use spaces only, no tabs.
* Start the server with `python start_server.py`. It is normal to see no output.
* To stop it, press Ctrl+C a few times.

## Commands and everything else

The full command list, hub system, testimony recording and the rest are documented in the [tsuserverCC README](https://github.com/RealKaiser/tsuserverCC#readme). In game, `/help` lists the commands and `/help <command>` explains one. The differences from tsuserverCC are listed above.

## License

This server is licensed under the AGPLv3 license. In short, if you use a modified version of tsuserverCC, you *must* distribute its source licensed under the AGPLv3 as well, and notify your users where the modified source may be found. The main difference between the AGPL and the GPL is that for the AGPL, network use counts as distribution. If you do not accept these terms, you should use [serverD](https://github.com/Attorney-Online-Engineering-Task-Force/serverD), which uses GPL rather than AGPL.

See the [LICENSE](LICENSE.md) file for more information.
