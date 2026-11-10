// Script manual pra DESVINCULAR a pubkey do device no server EV3.
// Útil quando:
//   - Scanner gerou keypair novo (perdeu o antigo)
//   - Servidor ainda tem a pubkey antiga cacheada pro IMEI/email
//   - Decrypt do sessionHmacSecret falha com "oaep decoding error"
//
// Fluxo:
//   1. Loga com Basic Auth → pega accessToken
//      (ignoramos sessionHmacSecret — não precisa decriptar)
//   2. POST /venia/ebrius com Bearer + {imei, email}
//      → server apaga a pubkey/IMEI daquele usuário
//   3. Próximo scan: login registra a nossa pubkey fresh
//
// Rode com: npm run reset-device
//
// Baseado em: ev3_app_vendas_promoter/lib/Pages/PDV/DesativarPDVEmpresa.dart:87-108

import ALVO from '../config.js';
import { coletarResposta } from './http.js';
import { montarBasic } from './auth.js';

async function resetarDevice() {
	console.log('');
	console.log('── Reset de device no server EV3 ──');
	console.log(`  Host  : ${ALVO.baseUrl}`);
	console.log(`  User  : ${ALVO.loginPayload.nmUsuario}`);
	console.log(`  IMEI  : ${ALVO.loginPayload.imei}`);
	console.log(`  Email : ${ALVO.emailParaRefresh}`);
	console.log('');

	// ─── 1. Login pra pegar accessToken ───────────────────────
	console.log('[1/2] Logando pra pegar accessToken...');
	const headers = { 'content-type': 'application/json' };
	if (ALVO.basicAuth?.usuario && ALVO.basicAuth?.senha) {
		headers['authorization'] = montarBasic(ALVO.basicAuth.usuario, ALVO.basicAuth.senha);
	}

	let respLogin;
	try {
		respLogin = await coletarResposta(ALVO.baseUrl + ALVO.rotas.login, {
			metodo: 'POST',
			headers,
			headersPadrao: ALVO.headersPadrao,
			body: JSON.stringify(ALVO.loginPayload),
		});
	} catch (erro) {
		console.error('  ✗ Falha HTTP no login:', erro.message);
		process.exit(1);
	}

	if (respLogin.status !== 200) {
		console.error(`  ✗ Login falhou: HTTP ${respLogin.status}`);
		console.error(`    Body: ${respLogin.corpo.slice(0, 200)}`);
		process.exit(1);
	}

	let accessToken;
	try {
		accessToken = JSON.parse(respLogin.corpo).accessToken;
	} catch {
		console.error('  ✗ Resposta do login não é JSON válido');
		process.exit(1);
	}
	if (!accessToken) {
		console.error('  ✗ accessToken ausente na resposta');
		process.exit(1);
	}
	console.log(`  ✓ Login OK, accessToken recebido (len=${accessToken.length})`);

	// ─── 2. Chamar /venia/ebrius ─────────────────────────────
	console.log('[2/2] Desvinculando device no server...');
	const corpoLogout = JSON.stringify({
		imei: ALVO.loginPayload.imei,
		email: ALVO.emailParaRefresh,
	});

	let respLogout;
	try {
		respLogout = await coletarResposta(ALVO.baseUrl + ALVO.rotas.logout, {
			metodo: 'POST',
			headers: {
				'content-type': 'application/json',
				authorization: `Bearer ${accessToken}`,
			},
			headersPadrao: ALVO.headersPadrao,
			body: corpoLogout,
		});
	} catch (erro) {
		console.error('  ✗ Falha HTTP no /venia/ebrius:', erro.message);
		process.exit(1);
	}

	console.log(`  → status: ${respLogout.status} ${respLogout.statusText}`);
	if (respLogout.corpo && respLogout.corpo.length > 0) {
		console.log(`  → body: ${respLogout.corpo.slice(0, 300)}`);
	}

	if (respLogout.status >= 200 && respLogout.status < 300) {
		console.log('');
		console.log('✓ Device desvinculado no server.');
		console.log('  Próximo scan vai registrar nossa pubkey atual.');
		console.log('  (Se quiser keypair totalmente novo: delete .keypair.pem antes)');
	} else {
		console.log('');
		console.log('✗ Logout respondeu status não-OK.');
		console.log('  Pode ser que o endpoint exija HMAC signing (tenta rodar scan com o');
		console.log('  mesmo keypair que gerou a pubkey do server pra confirmar).');
		console.log('  Ou pede pro backend resetar manualmente.');
	}
	console.log('');
}

resetarDevice().catch((e) => {
	console.error('Erro fatal:', e);
	process.exit(1);
});
