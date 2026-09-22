// Ponto de entrada do Scanner de Segurança.
// Fase 2 - Passo 2.2: auditoria de rede completa (HTTPS, headers de segurança).

import ALVO from './config.js';
import { criarMotor } from './utils/motor.js';
import { auditarRede } from './scanners/rede.js';
import { auditarCookies } from './scanners/cookies.js';
import { auditarJWT } from './scanners/jwt.js';
import { simularAtaques } from './scanners/ataques.js';
import { auditarSessao } from './scanners/sessao.js';
import { gerarRelatorio } from './utils/relatorio.js';

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

// Fase 2: rede/infraestrutura
await auditarRede(ALVO, motor);

// Fase 2 (Passo 2.3): cookies do login
await auditarCookies(ALVO, motor);

// Fase 3: JWT — quebra, decodificação Base64URL, validação de claims
await auditarJWT(ALVO, motor);

// Fase 4: ataques ativos — alg:none bypass e brute-force HMAC
await simularAtaques(ALVO, motor);

// Fase 5 (expansão A): fluxo de sessão — refresh, rotação, logout
await auditarSessao(ALVO, motor);

// Fase 5: consolida resumo e gera relatórios .md + .json
const resumo = motor.resumo();
const arquivos = gerarRelatorio(resumo, ALVO);
console.log(`Relatórios gerados:`);
console.log(`  ${arquivos.md}`);
console.log(`  ${arquivos.json}`);
