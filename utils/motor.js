// Motor de pontuação do scanner.
// Cada teste (checar HTTPS, checar cookie, checar JWT...) chama motor.registrar(...)
// passando um "achado". No fim, motor.resumo() imprime a nota final.

// ─── Cores ANSI ────────────────────────────────────────────────
// Terminais entendem essas sequências mágicas como comandos de cor.
// \x1b[32m = "a partir daqui, escreva em verde". \x1b[0m = "volta ao normal".
const CORES = {
  verde: '\x1b[32m',
  vermelho: '\x1b[31m',
  amarelo: '\x1b[33m',
  ciano: '\x1b[36m',
  cinza: '\x1b[90m',
  negrito: '\x1b[1m',
  reset: '\x1b[0m'
};

// ─── Tabela de penalidades ─────────────────────────────────────
// Cada falha detectada tira pontos da nota inicial (100).
// A gravidade decide quanto pesa. Você pode ajustar esses números depois.
const PENALIDADES = {
  baixa: 2,
  media: 5,
  alta: 10,
  critica: 20
};

// ─── Fábrica do motor ──────────────────────────────────────────
// Retorna um objeto com { registrar, resumo }. Usamos uma "closure":
// a lista `achados` fica escondida dentro da função, só quem tem o
// motor consegue mexer nela.
function criarMotor() {
  const achados = [];

  function registrar(achado) {
    achados.push(achado);
    imprimirAchado(achado);
  }

  function imprimirAchado(a) {
    const icone = a.passou
      ? `${CORES.verde}✓${CORES.reset}`
      : `${CORES.vermelho}✗${CORES.reset}`;
    const categoria = `${CORES.ciano}[${a.categoria}]${CORES.reset}`;
    console.log(`${icone} ${categoria} ${a.descricao}`);
    if (!a.passou && a.detalhes) {
      console.log(`   ${CORES.cinza}↳ ${a.detalhes}${CORES.reset}`);
    }
  }

  function resumo() {
    const total = achados.length;
    const passaram = achados.filter(a => a.passou).length;
    const falharam = total - passaram;

    let nota = 100;
    for (const a of achados) {
      if (!a.passou) {
        nota -= PENALIDADES[a.gravidade] || 0;
      }
    }
    nota = Math.max(0, nota); // nunca abaixo de zero

    const corNota =
      nota >= 80 ? CORES.verde :
      nota >= 50 ? CORES.amarelo :
                   CORES.vermelho;

    console.log('');
    console.log(`${CORES.negrito}═══ Resumo ═══${CORES.reset}`);
    console.log(`Testes rodados: ${total}`);
    console.log(`  ${CORES.verde}Passou: ${passaram}${CORES.reset}`);
    console.log(`  ${CORES.vermelho}Falhou: ${falharam}${CORES.reset}`);
    console.log('');
    console.log(`${CORES.negrito}Nota final: ${corNota}${nota}/100${CORES.reset}`);
    console.log('');

    return { total, passaram, falharam, nota, achados };
  }

  return { registrar, resumo };
}

export { criarMotor };
