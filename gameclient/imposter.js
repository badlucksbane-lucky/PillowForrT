// Imposter: 3 to 7 players, a hidden-role word game played in the room with the phones as private screens. Everyone but one player is sent the same secret word; the imposter is only told the
// category. Each player says one word about it out loud, the table argues, then everyone votes on their phone for who the imposter is. A caught imposter gets one guess at the word. Crew win
// by catching them and keeping the word safe (1 point each); the imposter wins by dodging the vote or guessing the word (2 points). The screen only ever shows the word at the end of a round.
// All secrets travel as private panels (ctx.panel), so nothing hidden is drawn on the shared screen. The rules are in step() and the pick handler, free of drawing and DOM, for scripts/dev/imposter-unit.mjs.
'use strict';
Games.register({
  id: 'imposter', name: 'Imposter', players: { min: 3, max: 7 }, orientation: 'any', widgets: [],
  create: function (ctx) {
    var WORDS = { // original lists: a category and a dozen things in it
      Animals: ['Giraffe', 'Penguin', 'Octopus', 'Kangaroo', 'Hedgehog', 'Dolphin', 'Camel', 'Owl', 'Squirrel', 'Crocodile', 'Flamingo', 'Moose'],
      Food: ['Pancake', 'Sushi', 'Burrito', 'Lasagne', 'Popcorn', 'Dumpling', 'Waffle', 'Curry', 'Omelette', 'Pretzel', 'Falafel', 'Porridge'],
      'At home': ['Toaster', 'Bathtub', 'Wardrobe', 'Doorbell', 'Curtain', 'Kettle', 'Fridge', 'Staircase', 'Carpet', 'Mirror', 'Lamp', 'Sofa'],
      Places: ['Library', 'Harbour', 'Airport', 'Castle', 'Desert', 'Aquarium', 'Lighthouse', 'Stadium', 'Volcano', 'Bakery', 'Museum', 'Island'],
      Jobs: ['Plumber', 'Pilot', 'Firefighter', 'Baker', 'Dentist', 'Farmer', 'Magician', 'Detective', 'Carpenter', 'Astronaut', 'Chef', 'Lifeguard'],
      Sports: ['Archery', 'Surfing', 'Fencing', 'Curling', 'Rowing', 'Boxing', 'Skiing', 'Cricket', 'Karate', 'Bowling', 'Rugby', 'Hockey'],
      Transport: ['Tram', 'Canoe', 'Helicopter', 'Scooter', 'Ferry', 'Tractor', 'Rocket', 'Taxi', 'Submarine', 'Bicycle', 'Cable car', 'Skateboard'],
      Clothes: ['Scarf', 'Wellies', 'Raincoat', 'Pyjamas', 'Mittens', 'Apron', 'Sandals', 'Cardigan', 'Helmet', 'Bow tie', 'Overalls', 'Poncho']
    };
    var CLUE_T = 30, DISCUSS_T = 60, VOTE_T = 45, REVEAL_T = 4, GUESS_T = 20;
    var s = { phase: 'deal', round: 0, t: 0, ids: [], order: [], idx: 0, cat: '', word: '', imposter: '', ready: {}, voted: {}, tally: {}, ejected: '', scores: {}, won: '', msg: '', options: [] };
    var cur = {}, voteMap = {}; // player id -> the panel that phone should be showing now; player id -> who each vote item means

    function pl(id) { var a = ctx.players(); for (var i = 0; i < a.length; i++) if (a[i].id === id) return a[i]; return null; }
    function name(id) { var p = pl(id); return p ? p.name : '?'; }
    function show(id, panel) { var p = pl(id); if (!p) return; cur[id] = panel; ctx.panel(p, panel); }
    function hide(id) { var p = pl(id); delete cur[id]; if (p) ctx.panel(p, null); }
    function hideAll() { s.ids.forEach(hide); }
    function pick(a) { return a[Math.floor(Math.random() * a.length)]; }
    function shuffle(a) { a = a.slice(); for (var i = a.length - 1; i > 0; i--) { var j = Math.floor(Math.random() * (i + 1)), t = a[i]; a[i] = a[j]; a[j] = t; } return a; }
    function pid() { return s.phase + s.round + ':' + s.idx; } // a panel's id: an answer to an older panel is ignored
    function present(id) { return s.ids.indexOf(id) >= 0 && !!pl(id); }
    function everyone() { return s.ids.filter(present); }

    function newRound() {
      var ps = ctx.players().slice().sort(function (a, b) { return a.slot - b.slot; });
      if (ps.length < 3) { ctx.end(); return; }
      hideAll();
      s.round++; s.ids = ps.map(function (p) { return p.id; });
      var cat = pick(Object.keys(WORDS)); s.cat = cat; s.word = pick(WORDS[cat]); s.imposter = pick(s.ids);
      s.phase = 'deal'; s.t = 0; s.idx = 0; s.ready = {}; s.voted = {}; s.tally = {}; s.ejected = ''; s.won = ''; s.msg = ''; s.options = [];
      s.ids.forEach(function (id) { if (s.scores[id] === undefined) s.scores[id] = 0; });
      s.ids.forEach(function (id) {
        show(id, { id: pid(), title: id === s.imposter ? 'You are the IMPOSTER. Category: ' + s.cat + '. Blend in.' : 'The word is ' + s.word, items: ['Got it'] });
      });
    }
    function startClues() {
      hideAll(); s.msg = ''; s.phase = 'clues'; s.order = shuffle(everyone()); s.idx = 0; nextSpeaker();
    }
    function nextSpeaker() {
      while (s.idx < s.order.length && !present(s.order[s.idx])) s.idx++;
      if (s.idx >= s.order.length) { startDiscuss(); return; }
      s.t = CLUE_T; hideAll();
      show(s.order[s.idx], { id: pid(), title: 'Say one word about it, out loud', items: ['Done'] });
    }
    function startDiscuss() {
      hideAll(); s.phase = 'discuss'; s.t = DISCUSS_T; s.ready = {}; s.idx = 0;
      everyone().forEach(function (id) { show(id, { id: pid(), title: 'Talk it over', items: ['Ready to vote'] }); });
    }
    function startVote() {
      hideAll(); s.phase = 'vote'; s.t = VOTE_T; s.voted = {}; s.idx = 0; voteMap = {};
      everyone().forEach(function (id) {
        var others = everyone().filter(function (o) { return o !== id; }); voteMap[id] = others;
        show(id, { id: pid(), title: 'Who is the imposter?', items: others.map(name) });
      });
    }
    function reveal() {
      hideAll(); s.phase = 'reveal'; s.t = REVEAL_T; s.tally = {};
      Object.keys(s.voted).forEach(function (v) { var t = s.voted[v]; s.tally[t] = (s.tally[t] || 0) + 1; });
      var max = 0, who = '', tie = false;
      Object.keys(s.tally).forEach(function (t) { if (s.tally[t] > max) { max = s.tally[t]; who = t; tie = false; } else if (s.tally[t] === max) tie = true; });
      s.ejected = !max || tie ? '' : who;
    }
    function afterReveal() {
      if (s.ejected === s.imposter) { // caught: one guess at the word
        s.phase = 'guess'; s.t = GUESS_T; s.idx = 0;
        var decoys = shuffle(WORDS[s.cat].filter(function (w) { return w !== s.word; })).slice(0, 3);
        s.options = shuffle(decoys.concat([s.word]));
        show(s.imposter, { id: pid(), title: 'Caught! Guess the word to win', items: s.options });
      } else finish(s.imposter);
    }
    function finish(winner) { // 'imposter' wins by id; the crew by ''
      hideAll(); s.phase = 'result'; s.idx = 0; s.won = winner ? 'imposter' : 'crew';
      if (winner) s.scores[s.imposter] += 2; else s.ids.forEach(function (id) { if (id !== s.imposter) s.scores[id]++; });
      var host = everyone()[0];
      if (host) show(host, { id: pid(), title: 'Another round?', items: ['Next round', 'Stop'] });
    }
    function step(dt) {
      if (s.t > 0) {
        s.t -= dt;
        if (s.t <= 0) {
          s.t = 0;
          if (s.phase === 'clues') { s.idx++; nextSpeaker(); }
          else if (s.phase === 'discuss') startVote();
          else if (s.phase === 'vote') reveal();
          else if (s.phase === 'reveal') afterReveal();
          else if (s.phase === 'guess') finish(''); // out of time: the crew take it
        }
      }
    }
    function onPick(p, id, i) {
      if (!cur[p.id] || cur[p.id].id !== id) return; // an answer to an old panel
      var ph = s.phase;
      if (ph === 'deal') { s.ready[p.id] = true; hide(p.id); if (everyone().every(function (x) { return s.ready[x]; })) startClues(); }
      else if (ph === 'clues') { if (p.id === s.order[s.idx]) { hide(p.id); s.idx++; nextSpeaker(); } }
      else if (ph === 'discuss') { s.ready[p.id] = true; hide(p.id); if (everyone().every(function (x) { return s.ready[x]; })) startVote(); }
      else if (ph === 'vote') {
        var t = voteMap[p.id] && voteMap[p.id][i]; if (!t) return;
        s.voted[p.id] = t; hide(p.id);
        if (everyone().every(function (x) { return s.voted[x]; })) reveal();
      } else if (ph === 'guess') { if (p.id === s.imposter) { hide(p.id); finish(s.options[i] === s.word ? 'imposter' : ''); } }
      else if (ph === 'result') { hide(p.id); if (i === 0) newRound(); else ctx.end(); }
    }
    function onLeave(p) {
      delete cur[p.id];
      if (ctx.players().length < 3) { ctx.end(); return; }
      if (s.ids.indexOf(p.id) < 0) return;
      if (p.id === s.imposter && s.phase !== 'result') { newRound(); s.msg = 'The imposter left. New round.'; return; } // the note stays until the clues start
      // anyone else: the round carries on without them
      if (s.phase === 'deal' && everyone().every(function (x) { return s.ready[x]; })) startClues();
      else if (s.phase === 'clues' && p.id === s.order[s.idx]) nextSpeaker();
      else if (s.phase === 'discuss' && everyone().every(function (x) { return s.ready[x]; })) startVote();
      else if (s.phase === 'vote' && everyone().every(function (x) { return s.voted[x]; })) reveal();
      else if (s.phase === 'result' && !Object.keys(cur).length) { var host = everyone()[0]; if (host) show(host, { id: pid(), title: 'Another round?', items: ['Next round', 'Stop'] }); }
    }
    function onHello(p) { if (cur[p.id]) ctx.panel(p, cur[p.id]); } // a phone that came back gets its panel again

    function render(g, w, h) {
      var k = Math.min(w / 800, h / 450), ox = (w - 800 * k) / 2, oy = (h - 450 * k) / 2;
      g.save(); g.translate(ox, oy); g.scale(k, k);
      g.fillStyle = '#1d1a14'; g.fillRect(0, 0, 800, 450); g.textAlign = 'center';
      var heads = { deal: 'Look at your phone', clues: 'One word each', discuss: 'Talk it over', vote: 'Vote for the imposter', reveal: 'The votes', guess: 'The imposter guesses the word', result: s.won === 'crew' ? 'The crew win' : 'The imposter wins' };
      g.font = '800 34px system-ui, sans-serif'; g.fillStyle = '#f1ebde'; g.fillText(s.msg || heads[s.phase] || '', 400, 56);
      g.font = '600 16px system-ui, sans-serif'; g.fillStyle = '#9b9384'; g.fillText('Round ' + s.round + (s.phase === 'clues' || s.phase === 'discuss' || s.phase === 'vote' || s.phase === 'guess' ? ' · ' + Math.ceil(s.t) + ' s' : ''), 400, 82);
      var ids = s.ids, n = ids.length, y0 = 118, rh = Math.min(48, 290 / Math.max(1, n));
      ids.forEach(function (id, i) {
        var p = pl(id), y = y0 + i * rh; if (!p) return;
        var speaking = s.phase === 'clues' && s.order[s.idx] === id, done = (s.phase === 'deal' || s.phase === 'discuss') && s.ready[id] || (s.phase === 'clues' && s.order.indexOf(id) < s.idx) || s.phase === 'vote' && s.voted[id];
        g.fillStyle = speaking ? '#2c261b' : 'rgba(0,0,0,0)'; g.fillRect(180, y - rh * 0.7, 440, rh * 0.92);
        g.fillStyle = p.color; g.beginPath(); g.arc(210, y - 6, 9, 0, 7); g.fill();
        g.textAlign = 'left'; g.font = '700 22px system-ui, sans-serif'; g.fillStyle = '#f1ebde'; g.fillText(p.name + (speaking ? '  ◂ speaking' : ''), 232, y);
        g.textAlign = 'right'; g.font = '700 20px system-ui, sans-serif'; g.fillStyle = '#d9b27a';
        var right = done ? '✓' : (s.phase === 'reveal' || s.phase === 'guess' || s.phase === 'result') && s.tally[id] ? s.tally[id] + (s.tally[id] === 1 ? ' vote' : ' votes') : '';
        if (s.phase === 'result') right = (s.tally[id] ? s.tally[id] + ' · ' : '') + (id === s.imposter ? 'IMPOSTER · ' : '') + s.scores[id] + ' pts';
        g.fillText(right, 610, y); g.textAlign = 'center';
      });
      g.font = '700 26px system-ui, sans-serif'; g.fillStyle = '#d9b27a';
      if (s.phase === 'reveal') g.fillText(s.ejected ? name(s.ejected) + ' is voted out' : 'No majority: nobody is voted out', 400, 420);
      if (s.phase === 'result') g.fillText('The word was ' + s.word + ' (' + s.cat + ')', 400, 420);
      if (s.phase === 'deal' || s.phase === 'discuss') { g.font = '600 18px system-ui, sans-serif'; g.fillStyle = '#9b9384'; g.fillText(s.phase === 'deal' ? 'Keep your phone to yourself' : 'Everyone ready? Tap on your phone', 400, 420); }
      g.restore();
    }
    newRound();
    return { s: s, step: step, onJoin: function () {}, onLeave: onLeave, onPick: onPick, onHello: onHello, tick: step, render: render, _cur: cur };
  }
});
