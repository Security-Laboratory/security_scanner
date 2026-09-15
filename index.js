// Ponto de entrada do Scanner de Segurança.
// Nesta versão: carrega o alvo, dispara alguns achados FAKE só pra
// demonstrar o motor de pontuação. Os testes reais entram nas próximas fases.

import ALVO from './config.js';
import { criarMotor } from './utils/motor.js';

const { baseUrl, rotas } = ALVO;

console.log('=== Scanner de Segurança v0.1 ===');
console.log('');
console.log(`Alvo: ${baseUrl}`);
console.log('Rotas mapeadas:');
for (const [nome, caminho] of Object.entries(rotas)) {
  console.log(`  ${nome.padEnd(10)} → ${baseUrl}${caminho}`);
}
console.log('');
console.log('─── Iniciando testes ───');
console.log('');

const motor = criarMotor();

// ⚠️ Achados FALSOS, só pra você ver o motor em ação.
// Nas próximas fases substituímos por testes de verdade.
motor.registrar({
  id: 'demo-passou',
  categoria: 'demo',
  descricao: 'Motor de pontuação está funcionando',
  gravidade: 'baixa',
  passou: true
});

motor.registrar({
  id: 'demo-falhou-alta',
  categoria: 'demo',
  descricao: 'Exemplo de falha de gravidade alta',
  gravidade: 'alta',
  passou: false,
  detalhes: 'Isto é só uma simulação, não um teste real ainda'
});

motor.registrar({
  id: 'demo-falhou-critica',
  categoria: 'demo',
  descricao: 'Exemplo de falha crítica',
  gravidade: 'critica',
  passou: false,
  detalhes: 'Simulando uma vulnerabilidade grave pra ver o placar'
});

motor.resumo();
