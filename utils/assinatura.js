// Assinatura HMAC-SHA256 dos requests sensíveis — mesmo esquema do app Flutter.
// Baseado em: ev3_app_vendas_promoter/lib/WebService/Services/dio_client.dart:149-176
//
// Fluxo:
//   1. Cliente pega sessionHmacSecret (recebido no login, Base64URL-encoded)
//   2. Decoda pra bytes
//   3. Monta mensagem: "timestamp|nonce|body" (pipe como separador)
//   4. Calcula HMAC-SHA256(mensagem, secretBytes)
//   5. Encoda digest em Base64URL sem padding
//   6. Põe em 3 headers: X-Ev3-Timestamp, X-Ev3-Nonce, X-Ev3-Signature
//
// Servidor faz o mesmo e compara. Bate → autentica. Não bate → rejeita.

import { createHmac, randomUUID } from 'node:crypto';

/**
 * Decoda Base64 (padrão OU URL-safe) → bytes.
 * Trata '-' e '_' como equivalentes a '+' e '/', e aplica padding '=' se faltar.
 * Aceita input vindo do backend em qualquer dos dois dialetos.
 */
function base64UrlParaBytes(str) {
	let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
	const padLen = (4 - (b64.length % 4)) % 4;
	b64 += '='.repeat(padLen);
	return Buffer.from(b64, 'base64');
}

/**
 * Encoda bytes → Base64URL sem padding.
 */
function bytesParaBase64Url(buf) {
	return buf
		.toString('base64')
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=+$/, '');
}

/**
 * Assina um body JSON e devolve os 3 headers que o backend espera.
 *
 * @param {string} body - corpo exato como vai ser enviado (string JSON já serializada)
 * @param {string} sessionHmacSecret - segredo em Base64URL (vindo do login)
 * @returns {{
 *   'X-Ev3-Timestamp': string,
 *   'X-Ev3-Nonce': string,
 *   'X-Ev3-Signature': string
 * }}
 */
function assinarRequisicao(body, sessionHmacSecret) {
	const timestamp = Math.floor(Date.now() / 1000).toString();
	const nonce = randomUUID().replace(/-/g, '');

	const keyBytes = base64UrlParaBytes(sessionHmacSecret);

	const mensagem = `${timestamp}|${nonce}|${body}`;

	const digest = createHmac('sha256', keyBytes).update(mensagem, 'utf-8').digest();
	const assinatura = bytesParaBase64Url(digest);

	if (process.env.DEBUG_SIGN === '1') {
		console.log('[sign] assinando request:');
		console.log('  timestamp:', timestamp);
		console.log('  nonce:', nonce);
		console.log('  body (len=' + body.length + '):', body);
		console.log(`  secret UTF-8 (len=${sessionHmacSecret.length}):`, sessionHmacSecret.slice(0, 40) + '...');
		console.log(`  keyBytes (len=${keyBytes.length}):`, keyBytes.slice(0, 10).toString('hex') + '...');
		console.log(`  mensagem (len=${mensagem.length}):`, mensagem.slice(0, 80) + '...');
		console.log('  signature:', assinatura);
	}

	return {
		'X-Ev3-Timestamp': timestamp,
		'X-Ev3-Nonce': nonce,
		'X-Ev3-Signature': assinatura,
	};
}

export { assinarRequisicao, base64UrlParaBytes, bytesParaBase64Url };
