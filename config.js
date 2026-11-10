// Alvo do scan atual. Importa o catálogo de rotas, seleciona UM host,
// e monta o payload de login no formato que a API da empresa espera.
//
// 🔒 CREDENCIAIS NUNCA FICAM AQUI.
// Rode com: npm run scan  (que usa node --env-file=.env)

import { generateKeyPairSync } from 'node:crypto';
import { HOSTS } from './rotas-empresa.js';

// Troque aqui pra escolher qual host atacar nesta rodada:
const HOST_ATIVO = HOSTS.evda;

// ─── Par de chaves RSA pro login ──────────────────────────────
// A API exige `publicKey` no body do login. Precisamos da PRIVADA pra
// decriptar o sessionHmacSecret que o servidor manda cifrado com a nossa pública.
//
// Persistência: salvamos o keypair em .keypair.pem (gitignored) depois do
// primeiro login bem-sucedido. Isso é essencial porque o servidor faz
// DEVICE BINDING — cacheia a pub key por IMEI. Keypair diferente = decrypt
// falha. Com persistência, o mesmo IMEI usa sempre o mesmo keypair.
//
// Pra RESETAR (ex: usar IMEI novo, ou reset manual no server): apagar
// o arquivo .keypair.pem e rodar de novo.
//
// FORMATO CRÍTICO da pubkey: Base64 do DER (SPKI) direto, SEM embrulho PEM.
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { createPrivateKey, createPublicKey } from 'node:crypto';

const CAMINHO_KEYPAIR = '.keypair.pem';

let privateKey;
let publicKeyBase64;

if (existsSync(CAMINHO_KEYPAIR)) {
	// Carrega do disco
	const pem = readFileSync(CAMINHO_KEYPAIR, 'utf-8');
	privateKey = createPrivateKey({ key: pem, format: 'pem' });
	const publicKey = createPublicKey(privateKey);
	publicKeyBase64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
	console.log(`[config] Keypair carregado de ${CAMINHO_KEYPAIR}`);
} else {
	// Gera novo
	const keyPair = generateKeyPairSync('rsa', { modulusLength: 2048 });
	privateKey = keyPair.privateKey;
	publicKeyBase64 = keyPair.publicKey
		.export({ type: 'spki', format: 'der' })
		.toString('base64');
	// Salva pra reusar
	const pem = privateKey.export({ type: 'pkcs8', format: 'pem' });
	writeFileSync(CAMINHO_KEYPAIR, pem, 'utf-8');
	console.log(`[config] Keypair novo gerado e salvo em ${CAMINHO_KEYPAIR}`);
}

const ALVO = {
	baseUrl: `https://${HOST_ATIVO}`,

	rotas: {
		login: '/api/Usuario/Logar',
		refresh: '/venia/reficite', // confirmado pelo app Flutter
		logout: '/venia/ebrius', // confirmado no auth_config.dart
		protegida: '/api/Empresa/ListarEmpresa',
	},

	// Payload que vai no body do POST /api/Usuario/Logar.
	// Credenciais DO USUÁRIO humano (nmUsuario, desSenha).
	loginPayload: {
		nmUsuario: process.env.USER_LOGIN,
		desSenha: process.env.USER_PASS,
		imei: process.env.APP_IMEI || '869440068442803',
		appVersion: process.env.APP_VERSION || '1.0.0',
		publicKey: publicKeyBase64,
	},

	// Email usado no payload de refresh (/venia/reficite exige Email + Imei)
	emailParaRefresh: process.env.APP_EMAIL || process.env.USER_LOGIN,

	// HTTP Basic Auth — identidade do APP/cliente (não do usuário humano).
	// Obrigatória pra /api/Usuario/Logar e pras rotas legadas (app-vendas-rota-legada).
	basicAuth: {
		usuario: process.env.APP_USER,
		senha: process.env.APP_PASS,
	},

	// Body que o scanner manda nas rotas protegidas com HMAC signing.
	// /api/Empresa/ListarEmpresa espera { emailUsuario: string }.
	// Vem de: ev3_app_vendas_promoter/lib/.../ListaEmpresaRequest.dart
	bodyProtegida: () =>
		JSON.stringify({
			emailUsuario: process.env.APP_EMAIL || process.env.USER_LOGIN,
		}),

	// Chave privada RSA (KeyObject) que casa com a publicKey enviada no login.
	// Usada pra decriptar o sessionHmacSecret que vem criptografado com a pub key.
	// Veja: utils/login.js + ev3_app_vendas_promoter/.../SecurityModule.kt:70-92
	privateKey,

	// Headers que o gateway EV3 espera em TODA requisição.
	// Vistos em: ev3_app_vendas_promoter/lib/WebService/Services/dio_client.dart:55
	// Sem isso, o gateway/WAF devolve 403 HTML antes mesmo de chegar na app.
	//
	// APP_CLIENT: no app Flutter está hardcoded como 'pdv-ios', mas se seu
	// usuário de teste está registrado em outra plataforma (Android), o backend
	// pode checar consistência. Default aqui é 'pdv-ios'; override via .env se precisar.
	headersPadrao: {
		'User-Agent': 'EV3-EVENT-API/1.0',
		'x-ev3-client': process.env.APP_CLIENT || 'pdv-ios',
	},
};

// Validação sanity
const faltam = [];
if (!ALVO.basicAuth.usuario) faltam.push('APP_USER');
if (!ALVO.basicAuth.senha) faltam.push('APP_PASS');
if (!ALVO.loginPayload.nmUsuario) faltam.push('USER_LOGIN');
if (!ALVO.loginPayload.desSenha) faltam.push('USER_PASS');

if (faltam.length > 0) {
	console.error('');
	console.error(`❌ Credenciais ausentes no .env: ${faltam.join(', ')}`);
	console.error('');
	console.error('   Seu .env precisa de:');
	console.error('     APP_USER=xxx    (Basic Auth do app — header)');
	console.error('     APP_PASS=xxx');
	console.error('     USER_LOGIN=xxx  (login do usuário — body nmUsuario)');
	console.error('     USER_PASS=xxx   (senha do usuário — body desSenha)');
	console.error('');
	process.exit(1);
}

// ─── Banner de config efetiva ────────────────────────────────
// Mostra o que o scanner realmente está usando. Se você mudou algo no .env
// e não vê a mudança aqui, o Node não carregou — veja --env-file e nomes.
console.log('');
console.log('── Config efetiva ──');
console.log(`  Host         : ${ALVO.baseUrl}`);
console.log(`  USER_LOGIN   : ${ALVO.loginPayload.nmUsuario}`);
console.log(`  APP_IMEI     : ${ALVO.loginPayload.imei}`);
console.log(`  APP_VERSION  : ${ALVO.loginPayload.appVersion}`);
console.log(`  APP_CLIENT   : ${ALVO.headersPadrao['x-ev3-client']}`);
console.log(`  APP_EMAIL    : ${ALVO.emailParaRefresh}`);
console.log(`  pub key      : ${publicKeyBase64.slice(0, 40)}...`);
console.log('');

export default ALVO;
