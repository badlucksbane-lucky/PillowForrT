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

Optional sensors, off unless a game asks: tilt (`DeviceMotion`, needs a tap on iOS) and vibration (not on iOS).

## Wire rules

- Continuous input (stick, tilt, pointer) goes on the **unordered** channel with a sequence number; the screen drops stale ones.
- Discrete events (buttons, choices) go on the **reliable** channel.
- Input is capped at about 30 messages a second per phone, so 7 phones stay under the box relay's 100 msg/s fallback.
- The screen sends state on the reliable channel and private views to one phone only.
- A game that loses a controller **pauses**, it does not end (the room grace period is 60 s).

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

## Build order (beads issues under pf-0fn)

1. Console and controller shell: screen page (code, QR, lobby, wake lock, start button for audio), controller page (`roomBounce`, widget renderer, orientation, iOS motion tap), input protocol.
2. Fort Pong: the smallest test of the pipeline and latency.
3. Sumo Push: many players, input rate, reconnects and pause.
4. Hidden-role game: private panel, per-phone views.
5. Phone test pass on the Pixel and Moto, plus an iOS check if a device is available.

## Gotchas (from the room channel work)

Pages reached from a QR must call `roomBounce` when signed out and set `joinPath`; request a wake lock on both sides; audio needs a tap on the screen; Chrome freezes a page whose screen is off, so controllers reconnect and the game pauses.
