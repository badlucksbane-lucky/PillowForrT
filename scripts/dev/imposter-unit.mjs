// Tests the rules of Imposter (gameclient/imposter.js) without a browser: players are made up, panels are recorded per phone, and answers are sent as the phone would (the panel's id and the index).
// Checks who is told what (the word never goes to the imposter nor onto the shared screen early), the turn order, stale answers, the timers, the vote and its tie rule, the imposter's guess, scoring,
// rounds, a phone that comes back, players leaving, and seven players.  Usage: node imposter-unit.mjs   Exit code 1 on failure.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const src = fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '../../gameclient/imposter.js'), 'utf8');
let game; new Function('Games', src)({ register: g => { game = g; } });
const fails = [];
const check = (name, ok, got) => { console.log((ok ? 'ok   ' : 'FAIL ') + name + (ok ? '' : '  got: ' + JSON.stringify(got))); if (!ok) fails.push(name); };

const mk = n => {
  const P = Array.from({ length: n }, (_, i) => ({ id: 'p' + i, slot: i, name: 'P' + i, color: '#fff', stick: { x: 0, y: 0 }, btn: {} }));
  const shown = {}, log = { ended: 0, sent: [] };
  const inst = game.create({ players: () => P, rumble() {}, panel: (p, d) => { shown[p.id] = d; log.sent.push([p.id, d]); }, audio: null, end: () => log.ended++ });
  const g = { P, inst, s: inst.s, shown, log };
  g.run = (sec, dt = 0.5) => { for (let t = 0; t < sec - 1e-9; t += dt) inst.step(dt); };
  g.answer = (id, i) => inst.onPick(g.P.find(p => p.id === id), shown[id] && shown[id].id, i);
  g.all = i => g.P.slice().forEach(p => { if (shown[p.id]) g.answer(p.id, i); });
  g.toClues = () => g.all(0);
  g.speaker = () => g.s.order[g.s.idx];
  g.toDiscuss = () => { g.toClues(); for (let i = 0; i < g.s.order.length; i++) g.answer(g.speaker(), 0); };
  g.toVote = () => { g.toDiscuss(); g.all(0); };
  g.voteFor = (voter, target) => { const items = g.shown[voter].items, i = items.indexOf(g.P.find(p => p.id === target).name); g.answer(voter, i); };
  g.texts = () => { const t = []; const c = new Proxy({}, { get: (_, k) => k === 'measureText' ? () => ({ width: 10 }) : k === 'fillText' ? (x) => t.push(String(x)) : () => {}, set: () => true }); inst.render(c, 800, 450); return t.join(' | '); };
  return g;
};
const ids = g => g.P.map(p => p.id);

check('3 to 7 players, no stick or buttons (the phones are panels)', game.players.min === 3 && game.players.max === 7 && game.widgets.length === 0, game);
{ // deal
  const g = mk(5), s = g.s;
  check('every phone gets a panel with Got it', ids(g).every(id => g.shown[id] && g.shown[id].items.length === 1 && g.shown[id].items[0] === 'Got it'), g.shown);
  const crew = ids(g).filter(id => id !== s.imposter);
  check('the crew are all told the same word', crew.every(id => g.shown[id].title === 'The word is ' + s.word), crew.map(id => g.shown[id].title));
  check('the imposter is told the category and not the word', g.shown[s.imposter].title.includes('IMPOSTER') && g.shown[s.imposter].title.includes(s.cat) && !g.shown[s.imposter].title.includes(s.word), g.shown[s.imposter].title);
  check('the shared screen does not show the word or who it is', !g.texts().includes(s.word) && !g.texts().includes('IMPOSTER'), g.texts());
  g.answer('p0', 0);
  check('the game waits until everyone has tapped', s.phase === 'deal' && !g.shown.p0 && !!g.shown.p1, s.phase);
  g.inst.onPick(g.P[1], 'wrong-id', 0);
  check('an answer with the wrong panel id is ignored', s.phase === 'deal' && !!g.shown.p1, s.phase);
  g.all(0);
  check('then the clue round starts', s.phase === 'clues' && s.order.length === 5, s.phase);
}
{ // clues
  const g = mk(4), s = g.s; g.toClues();
  const first = g.speaker(), others = ids(g).filter(i => i !== first);
  check('only the speaker has a panel', !!g.shown[first] && others.every(i => !g.shown[i]), g.shown);
  const stale = g.shown[first]; g.answer(others[0], 0);
  check("someone else's answer does nothing", g.speaker() === first, g.speaker());
  g.answer(first, 0);
  check('Done passes to the next speaker', g.speaker() !== first && !!g.shown[g.speaker()] && !g.shown[first], g.speaker());
  g.inst.onPick(g.P.find(p => p.id === first), stale.id, 0);
  check('a repeat of the old Done does not skip anyone', s.idx === 1, s.idx);
  g.run(31);
  check('a speaker who says nothing is passed over after 30 s', s.idx === 2, s.idx);
  g.answer(g.speaker(), 0); g.answer(g.speaker(), 0);
  check('after the last speaker comes the discussion, everyone with a Ready button', s.phase === 'discuss' && ids(g).every(i => g.shown[i] && g.shown[i].items[0] === 'Ready to vote'), s.phase);
}
{ // discuss and vote
  const g = mk(4), s = g.s; g.toDiscuss(); g.run(61);
  check('the discussion ends by itself after 60 s', s.phase === 'vote', s.phase);
  check('each phone gets the other players to vote for, not themselves', ids(g).every(i => { const it = g.shown[i].items; return it.length === 3 && !it.includes('P' + i.slice(1)); }), g.shown);
  const h = mk(4); h.toDiscuss(); h.all(0);
  check('everyone ready starts the vote early', h.s.phase === 'vote', h.s.phase);
  const t = h.s.imposter, [a, b, c, d] = ids(h);
  ids(h).forEach(v => { if (v !== t) h.voteFor(v, t); });
  check('the game waits for the imposter too', h.s.phase === 'vote', h.s.phase);
  h.voteFor(t, ids(h).find(i => i !== t));
  check('when all have voted the votes are shown', h.s.phase === 'reveal' && h.s.tally[t] === 3 && h.s.ejected === t, [h.s.phase, h.s.tally, h.s.ejected]);
  check('the screen shows the votes but still not the word', h.texts().includes('3 votes') && !h.texts().includes(h.s.word), h.texts());
}
{ // caught, right guess / wrong guess / out of time
  const play = guessIdx => {
    const g = mk(4), s = g.s; g.toVote(); const t = s.imposter;
    ids(g).forEach(v => g.voteFor(v, v === t ? ids(g).find(i => i !== t) : t)); g.run(4.5);
    return { g, s, t };
  };
  const { g, s, t } = play();
  check('a caught imposter gets four words to choose from, one of them right', s.phase === 'guess' && g.shown[t].items.length === 4 && g.shown[t].items.includes(s.word) && new Set(g.shown[t].items).size === 4, g.shown[t]);
  check('nobody else has a panel while they guess', ids(g).filter(i => i !== t).every(i => !g.shown[i]), g.shown);
  g.answer(t, g.shown[t].items.indexOf(s.word));
  check('the right word: the imposter wins and scores 2', s.phase === 'result' && s.won === 'imposter' && s.scores[t] === 2 && ids(g).filter(i => i !== t).every(i => s.scores[i] === 0), [s.won, s.scores]);
  const w = play(); w.g.answer(w.t, w.g.shown[w.t].items.findIndex(x => x !== w.s.word));
  check('a wrong word: the crew win and score 1 each, the imposter nothing', w.s.won === 'crew' && w.s.scores[w.t] === 0 && ids(w.g).filter(i => i !== w.t).every(i => w.s.scores[i] === 1), [w.s.won, w.s.scores]);
  const o = play(); o.g.run(21);
  check('no guess in 20 s counts as wrong', o.s.phase === 'result' && o.s.won === 'crew', o.s.phase);
  check('only the imposter can answer the guess', (() => { const x = play(); const other = ids(x.g).find(i => i !== x.t); x.g.inst.onPick(x.g.P.find(p => p.id === other), 'guess', 0); return x.s.phase === 'guess'; })(), null);
  check('the result shows the word and the scores', g.texts().includes(s.word) && g.texts().includes('IMPOSTER') && g.texts().includes('pts'), g.texts());
}
{ // not caught
  const g = mk(4), s = g.s; g.toVote(); const t = s.imposter, other = ids(g).filter(i => i !== t);
  ids(g).forEach(v => g.voteFor(v, v === other[0] ? other[1] : other[0]));
  g.run(4.5);
  check('voting out the wrong person: the imposter wins at once for 2', s.phase === 'result' && s.won === 'imposter' && s.scores[t] === 2, [s.phase, s.scores]);
  const h = mk(4); h.toVote(); const t2 = h.s.imposter, o2 = ids(h).filter(i => i !== t2);
  h.voteFor(o2[0], o2[1]); h.voteFor(o2[1], o2[0]); h.voteFor(o2[2], o2[1]); h.voteFor(t2, o2[0]); // two players on two votes each
  check('a tie votes nobody out, and the imposter wins', h.s.ejected === '' && h.texts().includes('No majority') && (h.run(4.5), h.s.won === 'imposter'), [h.s.ejected, h.s.won]);
  const k = mk(3); k.toVote(); k.run(46);
  check('nobody voting in 45 s: no majority, imposter wins', k.s.phase === 'reveal' && k.s.ejected === '', k.s.phase);
}
{ // next round / stop
  const g = mk(3), s = g.s; g.toVote(); g.run(46); g.run(4.5);
  check('the first player gets Next round and Stop', s.phase === 'result' && g.shown.p0 && g.shown.p0.items.join() === 'Next round,Stop' && !g.shown.p1, g.shown);
  g.answer('p1', 0);
  check("someone else's answer does not start it", s.phase === 'result', s.phase);
  const sc = JSON.stringify(s.scores); g.answer('p0', 0);
  check('Next round: round 2, scores kept, new secrets dealt', s.round === 2 && s.phase === 'deal' && JSON.stringify(s.scores) === sc && ids(g).every(i => g.shown[i] && g.shown[i].id.startsWith('deal2')), [s.round, s.phase]);
  g.toVote(); g.run(46); g.run(4.5); g.answer('p0', 1);
  check('Stop ends the game', g.log.ended === 1, g.log.ended);
}
{ // coming back and leaving
  const g = mk(4); g.shown.p2 = undefined; g.inst.onHello(g.P[2]); const sent = g.log.sent.length;
  g.inst.onHello(g.P[1]);
  check('a phone that says hello again gets its panel back', g.log.sent.length === sent + 1 && g.log.sent[g.log.sent.length - 1][0] === 'p1' && g.log.sent[g.log.sent.length - 1][1].title.length > 0, g.log.sent.slice(-2));
  g.answer('p1', 0); const n2 = g.log.sent.length; g.inst.onHello(g.P[1]);
  check('and nothing when it has none (it already answered)', g.log.sent.length === n2, null);
  const h = mk(4), im = h.s.imposter; const gone = h.P.splice(h.P.findIndex(p => p.id === im), 1)[0]; h.inst.onLeave(gone);
  check('if the imposter leaves the round starts again with a new one', h.s.round === 2 && h.s.imposter !== im && h.s.msg.includes('imposter left') && h.log.ended === 0, [h.s.round, h.s.msg]);
  const j = mk(4); j.toVote(); const t = j.s.imposter, out = ids(j).find(i => i !== t);
  ids(j).filter(i => i !== out).forEach(v => j.voteFor(v, ids(j).find(x => x !== v && x !== out) || t));
  const jp = j.P.splice(j.P.findIndex(p => p.id === out), 1)[0]; j.inst.onLeave(jp);
  check('a player who leaves after the others have voted does not hold up the vote', j.s.phase === 'reveal', j.s.phase);
  const m = mk(3); m.P.pop(); m.inst.onLeave({ id: 'p2' });
  check('with fewer than three players the game ends', m.log.ended === 1, m.log);
}
{ // seven players, a whole round
  const g = mk(7), s = g.s; g.toVote(); const t = s.imposter;
  ids(g).forEach(v => g.voteFor(v, v === t ? ids(g).find(i => i !== t) : t)); g.run(4.5);
  g.answer(t, g.shown[t].items.indexOf(s.word));
  check('seven players get all the way through a round', s.phase === 'result' && Object.keys(s.scores).length === 7 && s.scores[t] === 2, [s.phase, s.scores]);
  check('the words are all different, in eight categories of twelve', (() => { const seen = new Set(); for (let i = 0; i < 40; i++) { const x = mk(3); seen.add(x.s.cat + '/' + x.s.word); } return seen.size > 10; })(), null);
}
console.log(fails.length ? `\n${fails.length} FAILED` : '\nall ok');
process.exit(fails.length ? 1 : 0);
