// Alvo do scan atual. Importa o catálogo de rotas, seleciona UM host,
// e monta o payload de login no formato que a API da empresa espera.
//
// 🔒 CREDENCIAIS NUNCA FICAM AQUI.
// Rode com: npm run scan  (que usa node --env-file=.env)

import { generateKeyPairSync } from 'node:crypto';
import { HOSTS } from './rotas-empresa.js';

// Troque aqui pra escolher qual host atacar nesta rodada:
const HOST_ATIVO = HOSTS.evda;

// ─── Chave pública pro login ───────────────────────────────────
// A API exige `publicKey` no body do login. Duas formas de fornecer:
//   1. Via .env (PUBLIC_KEY = Base64 do DER SPKI) — útil pra reproduzir
//      exatamente o que o scanner mandou no Postman.
//   2. Gerada em memória a cada run — simula um device novo.
//
// FORMATO CRÍTICO: Base64 do DER (SPKI) direto, SEM embrulho PEM.
// Formato visto em:
//   ev3_app_vendas_promoter/android/.../SecurityModule.kt:39-42
//     Base64.encodeToString(kp.public.encoded, Base64.DEFAULT)
// Se mandar PEM com "-----BEGIN", o parser do backend quebra.

let publicKeyBase64;
if (process.env.PUBLIC_KEY) {
	publicKeyBase64 = process.env.PUBLIC_KEY;
} else {
	const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
	publicKeyBase64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
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

export default ALVO;
