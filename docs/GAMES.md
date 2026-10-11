# Game system design (epic pf-0fn)

Decided 2026-10-11 with Ben. Design the controller top down from a small standard input set, and only build games that fit it.

## Decisions

- **Screen:** a laptop browser (the console). It runs the game, is authoritative, draws a canvas and plays all audio. The box only does rendezvous (room channel, see HANDOFF.md "Room channel").
- **Controllers:** phones, portrait or landscape, **iOS must work** (motion needs a tap first; iOS has no vibration).
- **Own code, not a framework.** The room channel already provides rendezvous, direct WebRTC, resume and QR join. The only third-party piece considered is nipplejs (MIT) for the stick, and we may write that ourselves.
- **First three games:** Fort Pong (2 players), Sumo Push (up to 8), a hidden-role game (4 to 8). Later: Tap Race, Draw & Guess, a card table.

## Standard input set

A game declares the widgets it uses; the controller page builds itself from that list.

1. **Stick**: analog 2-axis (d-pad mode is a variant).
2. **Buttons**: up to 4 (A, B, X, Y), with press and release events.
3. **Pointer pad**: touch area reporting position, tap and swipe.
4. **Private panel**: the screen sends a list, cards or text to one phone; the phone returns a choice index. Covers every hidden-information game.
5. **Canvas input**: strokes and text entry (used by Draw & Guess, later).

Optional sensors, off unless a game asks: tilt (`deviceorientation`, beta and gamma in degrees; iOS asks permission from a tap, so the phone shows an "Enable tilt" button) and vibration (not on iOS). The canvas-input widget (strokes, text) is **not built yet**; it comes with Draw & Guess.

## Wire rules

- Continuous input (stick, tilt, pointer) goes on the **unordered** channel with a sequence number; the screen drops stale ones.
- Discrete events (buttons, choices) go on the **reliable** channel.
- Input is capped at about 30 messages a second per phone, so 7 phones stay under the box relay's 100 msg/s fallback.
- The screen sends state on the reliable channel and private views to one phone only.
- A game that loses a controller **pauses**, it does not end (the room grace period is 60 s). A controller counts as away when the box says so **or when the screen has heard nothing from it for 4 s** (the phone sends a heartbeat every second): a closed tab's data channel can look open for half a minute. "Continue without" drops the player.
- A stick is let go if it goes quiet for 600 ms while held (a lost release on the unordered channel must not leave it stuck); a release goes on both channels; a touch or release is sent at once, moves at most every 33 ms.
- Coordinates: stick x right and y down, -1 to 1 (dead zone 0.12; d-pad mode gives -1, 0 or 1); pointer 0 to 1 inside its area. Each input kind has its own sequence number and a `hello` resets it.

## Game module contract (sketch)

```
{ id, name, players: {min, max}, widgets: [...],
  orientation: 'any' | 'portrait' | 'landscape',
  start(ctx), onInput(playerId, input), tick(dt), render(canvas), privateView(playerId) }
```

## Sources and licences (checked 2026-10-11 from each repo's page; maintenance not verified)

| Source | Licence | Use |
|---|---|---|
| Air Jam | MIT | may adapt code; study its SDK shape |
| Open Party Lab | Apache-2.0 (assets excluded, see its NOTICE.md) | may adapt code; study its minigame API |
| netplayjs | ISC | may adapt code; Pong demo |
| HexStacker-Party | none stated | read for ideas only, do not copy |
| Freewee | none stated | ideas only |
| Couchfriends Controller-API | none stated, loads from their CDN | skip |
| AlecM33/Werewolf | GPL-3.0 | ideas only |
| EmulatorJS | GPL-3.0 (cores vary) | later, homebrew and public-domain only |
| AirConsole | proprietary, no self-hosting | design reference only |

"None stated" means all rights reserved. Public-domain rules (Pong, Snake, Hangman) are free to implement.

## Game ideas by input

| Input | Games |
|---|---|
| Stick + 1 or 2 buttons | Fort Pong, Air Hockey, Sumo Push, Snake Arena, Tank Duel, Light Trails, Capture the Flag |
| Tap only | Tap Race, Reaction Duel, Whack-a-Mole, Rhythm Tap, Co-op Meteor Stop |
| Tilt (optional) | Marble Maze race, Balance Table |
| Private panel, choice list | Hidden-role (Werewolf or Imposter style), Quiz buzz-in, Liar's Dice, Auction |
| Private panel, cards | Card table, Memory Pairs |
| Canvas input | Draw & Guess, Telephone |
| Gestures | Stacker, Fruit-slice swipe |

## What is built (pf-0fn.1, the shell)

- `/play` (`play.html`, `gameclient/console.js`): the screen. Room code, QR, player chips, game picker, Start (a tap, so the audio context may start), fullscreen, wake lock, pause overlay with "Continue without", Menu back to the lobby, "New room" if the box forgot the room.
- `/pad` (`pad.html`, `gameclient/pad.js`): the phone. Name and code (a scanned `#CODE` fills it in, a tap joins; a reload returns to the same place), builds the widgets from the game's list (stick, d-pad, buttons, pointer, tilt, private panel), portrait layout with thumbs at the bottom, status overlay, vibration, wake lock.
- `/game/<file>.js` serves `gameclient/*.js` (embedded, plain file names only). Both pages call `roomBounce` when there is no session (`game.go`).
- `gameclient/padtest.js`: a throwaway game that exercises every widget. Real games register the same way: `Games.register({id, name, players, widgets, orientation, create(ctx)})`; add the file in `gameclient/` and a script tag in `play.html`.
- Tests: `node scripts/dev/game-test.mjs` (screen plus phone-sized pages in headless Chromium against the real room server; about 15 s; checks join, every widget, two touches at once, panels, out-of-order and lost input, a full room, pause and the same place back, and that a deliberately broken ordering or heartbeat rule fails) and `go test -run TestGame .`. **Deployed, and tried by Ben with Chromium on the Pi as the screen and the Moto and Pixel as controllers: everything worked. Not yet tried: iOS, landscape on a real phone, more than two phones.**
- Found while testing: a tab behind the others in headless Chromium never answers a touch and has its timers held back, so the test brings each page to the front first; Chromium has `DeviceOrientationEvent.requestPermission` and fires one empty orientation event when a listener is added, which the pad ignores.

## Fort Pong (pf-0fn.2)

`gameclient/fortpong.js`. Two players, the stick's vertical axis moves the paddle (460 px/s at full tilt), A serves (only the server's A; the player who lost the point serves), first to 7, A again for a rematch with the serve passed on. Ball starts at 330 px/s, speeds up 7 % per paddle hit up to 760, and leaves the paddle at up to 55 degrees by where it hit. The ball moves in steps of at most 6 px so a fast one cannot skip a paddle. A hit buzzes the hitter's phone for 30 ms, a lost point buzzes the loser for 120 ms; beeps play on the screen once the audio context is running. The field is 800 by 450 scaled to fit with battlements top and bottom. A player leaving ends the game (it needs two); a phone that goes quiet pauses it like any other game.

Tests: `node scripts/dev/pong-unit.mjs` (rules without a browser: serve, walls, paddle hits, speed cap, a fast ball not tunnelling, scoring, serve order, winning, rematch; removing the speed cap makes it fail) and a two-phone section in `game-test.mjs`. In that test the screen tab sits behind the phone tabs, and a hidden tab gets no animation frames, so the test advances the game by hand with `gc.inst.tick`. **Not yet played on real phones; the feel at about 42 ms is the thing to judge.** Tuning values are the constants at the top of `create()`.

## Sumo Push (pf-0fn.3)

`gameclient/sumopush.js`. **2 to 7 players, not 8**: a room has 8 places and the screen takes one (the epic said 8). Round arena (radius 205 on an 800 by 450 field) that holds for 6 s then closes at 5 px/s down to 95. The stick pushes your disc (acceleration 700, drag 2.0, so about 350 px/s flat out); A is a dash of 520 px/s the way the stick points (or the way you are moving, or your nose when still), lasting 0.35 s during which the disc counts as 2.2 times heavier so it hits harder, with a 1.6 s cooldown shown as a ring. Discs bounce (0.9) and are stepped at most 10 px at a time so none passes through another. A disc whose centre leaves the arena is out (that phone buzzes 150 ms, hard hits buzz both phones up to 60 ms); last one on takes the round, first to 3 rounds wins, A for a rematch. A 3-second countdown starts every round and nobody moves in it; a draw scores nobody. Someone arriving mid-round watches until the next round; a player leaving is out, and under two players the game ends. A phone that goes quiet pauses it like any game.

Tests: `node scripts/dev/sumo-unit.mjs` (rules without a browser; breaking the collision impulse makes two checks fail) and a two-phone section in `game-test.mjs`. **Not yet played on real phones, and never with more than two.** Tuning values are the constants at the top of `create()`.

## Imposter (pf-0fn.4), the hidden-role game

`gameclient/imposter.js`. 3 to 7 players (the brief said 4 to 8; 7 is the room limit and 3 is the smallest that works), no stick or buttons: the phones are **private panels**. Everyone but one random player is told the same secret word (8 categories of 12, written for this project); the imposter is told only the category. Flow: everyone taps *Got it*; each player in a random order gets a *Done* button and says one word about it out loud (30 s, then skipped); *Talk it over* for 60 s or until all tap *Ready to vote*; everyone votes on their phone (the others as choices, 45 s); the votes are shown; the unique top vote is out, a tie or no votes means nobody is. A caught imposter gets four words (the real one and three from the category) and 20 s to pick: right means the imposter wins. Scores: crew win 1 each, imposter win 2. The first player gets *Next round* or *Stop*. The word and the imposter appear on the shared screen only on the result page; the unit test checks the shared screen never draws the word before that and that the imposter's panel never contains it.

Panels: `ctx.panel(p, {id, title, items})` shows a panel on one phone, `ctx.panel(p, null)` clears it, and the phone answers with `{id, index}`; an answer to an old panel id is ignored, so a late or repeated tap cannot skip anyone. Two shell changes came with it: the pad **keeps its panel across a pause or resume** (those rebuild the page), and the console calls the game's optional **`onHello(p)`** when a phone says hello again (a reload or reconnect), so a game can send that phone its panel again.

Tests: `node scripts/dev/imposter-unit.mjs` (every phase, the timers, stale and wrong-player answers, the tie rule, the guess, scoring, rounds, leaving, a phone returning, seven players; telling the imposter the word makes it fail) and a three-phone section in `game-test.mjs` (private panels arrive, the shared screen shows no word, a rebuilt and a reloaded phone keep their panel, the whole round through the votes and Stop; removing `onHello` makes the reload check fail). **Not yet played on real phones, and never with people talking.** Words and timers are constants at the top of `create()`.

## Build order (beads issues under pf-0fn)

1. Console and controller shell: screen page (code, QR, lobby, wake lock, start button for audio), controller page (`roomBounce`, widget renderer, orientation, iOS motion tap), input protocol.
2. Fort Pong: the smallest test of the pipeline and latency.
3. Sumo Push: many players, input rate, reconnects and pause.
4. Hidden-role game: private panel, per-phone views.
5. Phone test pass on the Pixel and Moto, plus an iOS check if a device is available.

## Gotchas (from the room channel work)

Pages reached from a QR must call `roomBounce` when signed out and set `joinPath`; request a wake lock on both sides; audio needs a tap on the screen; Chrome freezes a page whose screen is off, so controllers reconnect and the game pauses.
