// Drew every sprite from a small character grid so the art stayed hand-placed pixels.
const PALETTE = { o: '#5c6066', w: '#ffffff', b: '#e3f1fe', g: '#c4dcf3', O: '#ff5e24', k: '#232629', e: '#6c3200', c: '#f5e6dc' };

const SPRITES = {
  cloud: [
    '.........oooooo.........',
    '.......oowwwwwwoo.......',
    '....ooowwwwwwwwwwooo....',
    '..oowwwwwwwwwwwwwwwwoo..',
    '.owwwwwwwwwwwwwwwwwwwwo.',
    'owwwwwwwwwwwwwwwwwwwwwwo',
    'owwbbbbbbbbbbbbbbbbbbwwo',
    '.obbggggggggggggggggbbo.',
    '..ooooooooooooooooooooo.',
  ],
  cat: [
    '.O..........O.',
    '.OO........OO.',
    '.OOOOOOOOOOOO.',
    'OOOOOOOOOOOOOO',
    'OOkkOOOOOOkkOO',
    'OOkkOOOOOOkkOO',
    'OOOOOOeeOOOOOO',
    'OOOOOeOOeOOOOO',
    '.OOOOOOOOOOOO.',
    '..OOOwwwwOOO..',
    '..OOwwwwwwOO..',
    '..OOwwwwwwOO..',
    '..OOOOOOOOOO..',
    '..OO.OOOO.OO..',
  ],
  table: ['kkkkkkkkkk', 'kOOOOOOOOk', 'kkkkkkkkkk', 'kbbkbbkbbk', 'kkkkkkkkkk', 'kbbkbbkbbk', 'kkkkkkkkkk'],
  up: ['....O....', '...OOO...', '..OOOOO..', '.OOOOOOO.', '...OOO...', '...OOO...', '...OOO...', '...OOO...'],
  down: ['...OOO...', '...OOO...', '...OOO...', '...OOO...', '.OOOOOOO.', '..OOOOO..', '...OOO...', '....O....'],
  shield: ['kkkkkkkk', 'kOOOOOOk', 'kOOkkOOk', 'kOOkkOOk', 'kOOOOOOk', '.kOOOOk.', '..kOOk..', '...kk...'],
  check: ['.......G', '......GG', 'G....GG.', 'GG..GG..', '.GGGG...', '..GG....'],
};

// Turned a named grid into crisp inline SVG rectangles at the requested pixel size.
function sprite(name, scale) {
  const rows = SPRITES[name];
  const width = Math.max(...rows.map((r) => r.length));
  const rects = rows.flatMap((row, y) =>
    [...row].map((ch, x) => (ch === '.' ? '' : `<rect x="${x}" y="${y}" width="1" height="1" fill="${PALETTE[ch] || '#2ea44f'}"/>`)),
  );
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${rows.length}" width="${width * scale}" height="${rows.length * scale}" shape-rendering="crispEdges" aria-hidden="true">${rects.join('')}</svg>`;
}

// Filled every placeholder on the page with the sprite it asked for.
function paintSprites() {
  document.querySelectorAll('[data-sprite]').forEach((el) => {
    el.innerHTML = sprite(el.dataset.sprite, Number(el.dataset.scale || 4));
  });
}

paintSprites();
