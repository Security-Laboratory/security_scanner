// Helper único de login — centraliza a complexidade de montar o header
// Basic Auth + body JSON do payload de login. Usado por todos os scanners
// que precisam de um accessToken pra testar.
//
// IMPORTANTE: o servidor manda `sessionHmacSecret` CRIPTOGRAFADO com a
// publicKey que a gente enviou no login (RSA-OAEP SHA-256). Aqui a gente
// DECRIPTA usando a privateKey (que vive em memória no scanner, não em
// hardware) e devolve o segredo em claro — pronto pra usar como chave HMAC.
// Sem esse passo, cada request assinado dá 401.

import { privateDecrypt, constants } from 'node:crypto';
import { coletarResposta } from './http.js';
import { montarBasic } from './auth.js';

/**
 * Decripta o sessionHmacSecret vindo do servidor.
 *
 * Fluxo (idêntico ao SecurityModule.kt:70-92 do app Android):
 *   1. Base64URL → bytes (o secret criptografado)
 *   2. RSA-OAEP com nossa privada → bytes em claro
 *   3. UTF-8 → string (o segredo pronto pra usar)
 *
 * O servidor pode estar usando qualquer combinação de hashes OAEP.
 * Tentamos as mais comuns em ordem; a primeira que funcionar é a boa.
 * Em runs seguintes, cacheamos a combinação vencedora pra não tentar tudo.
 */
let OAEP_VENCEDOR = null; // cache da combinação que funciona nesta sessão

function decriptarHmacSecret(secretCifrado, privateKey) {
	// Base64URL → bytes (inverter trocas e repor padding)
	let b64 = secretCifrado.replace(/-/g, '+').replace(/_/g, '/');
	const padLen = (4 - (b64.length % 4)) % 4;
	b64 += '='.repeat(padLen);
	const ciphertext = Buffer.from(b64, 'base64');

	// Só OAEP. Removemos PKCS1 v1.5 porque ele passa validação de padding
	// mesmo com chave errada (retorna lixo) — vira falso positivo perigoso.
	const combos = OAEP_VENCEDOR
		? [OAEP_VENCEDOR]
		: [
				{ oaepHash: 'sha256', mgf1Hash: 'sha256', nome: 'OAEP-SHA256/SHA256' },
				{ oaepHash: 'sha256', mgf1Hash: 'sha1',   nome: 'OAEP-SHA256/SHA1' },
				{ oaepHash: 'sha1',   mgf1Hash: 'sha1',   nome: 'OAEP-SHA1/SHA1' },
				{ oaepHash: 'sha1',   mgf1Hash: 'sha256', nome: 'OAEP-SHA1/SHA256' },
			];

	let ultimoErro = null;
	for (const combo of combos) {
		try {
			const plaintext = privateDecrypt(
				{
					key: privateKey,
					padding: constants.RSA_PKCS1_OAEP_PADDING,
					oaepHash: combo.oaepHash,
					mgf1Hash: combo.mgf1Hash,
				},
				ciphertext,
			);

			// Validação: plaintext deve ser Base64 (padrão OU URL-safe).
			// Se vier lixo binário, descartamos (falso positivo de padding).
			const texto = plaintext.toString('utf-8');
			if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(texto)) {
				ultimoErro = new Error('plaintext decriptado não é Base64 — chave errada ou padding inválido');
				continue;
			}

			if (!OAEP_VENCEDOR) {
				OAEP_VENCEDOR = combo;
				console.log(`[sign] ✓ OAEP descoberto: ${combo.nome}`);
			}
			return texto;
		} catch (err) {
			ultimoErro = err;
		}
	}
	throw new Error(
		`Nenhum padding funcionou. Último erro: ${ultimoErro?.message}`,
	);
}

/**
 * Faz login na API e devolve os campos relevantes.
 *
 * @returns {Promise<{
 *   status: number,
 *   corpo: string,
 *   accessToken: string | null,
 *   refreshToken: string | null,
 *   sessionHmacSecret: string | null,
 *   expiresIn: number | null,
 *   setCookies: string[],
 *   erro: string | null
 * }>}
 */
async function fazerLogin(alvo) {
	const headers = { 'content-type': 'application/json' };

	// Rota de login exige HTTP Basic Auth (identidade do app).
	if (alvo.basicAuth?.usuario && alvo.basicAuth?.senha) {
		headers['authorization'] = montarBasic(alvo.basicAuth.usuario, alvo.basicAuth.senha);
	}

	const requestBody = JSON.stringify(alvo.loginPayload);

	const resp = await coletarResposta(alvo.baseUrl + alvo.rotas.login, {
		metodo: 'POST',
		headers,
		headersPadrao: alvo.headersPadrao,
		body: requestBody,
	});

	// Tenta parsear o body de resposta (pode falhar se backend devolveu HTML de erro)
	let respBody = {};
	try {
		respBody = JSON.parse(resp.corpo);
	} catch {
		// deixa respBody = {} e segue; o chamador decide o que fazer
	}

	// Decripta sessionHmacSecret se veio e a gente tem privateKey.
	let sessionHmacSecret = respBody.sessionHmacSecret || null;
	const sessionHmacSecretCifrado = sessionHmacSecret;
	if (sessionHmacSecret && alvo.privateKey) {
		try {
			sessionHmacSecret = decriptarHmacSecret(sessionHmacSecret, alvo.privateKey);
			if (process.env.DEBUG_SIGN === '1') {
				console.log('[sign] ✓ decrypt OK');
				console.log(`  cifrado (len=${sessionHmacSecretCifrado.length}):`, sessionHmacSecretCifrado.slice(0, 50) + '...');
				console.log(`  claro  (len=${sessionHmacSecret.length}):`, sessionHmacSecret.slice(0, 50) + '...');
			}
		} catch (err) {
			console.error('[sign] ✗ Falha ao decriptar sessionHmacSecret:', err.message);
			if (process.env.DEBUG_SIGN === '1') {
				console.error('  cifrado completo:', sessionHmacSecretCifrado);
			}
			sessionHmacSecret = null;
		}
	}

	return {
		status: resp.status,
		corpo: resp.corpo,
		setCookies: resp.setCookies,
		accessToken: respBody.accessToken || respBody.access_token || respBody.token || null,
		refreshToken: respBody.refreshToken || respBody.refresh_token || null,
		sessionHmacSecret,
		expiresIn: respBody.expiresIn || null,
		erro: resp.status >= 400 ? `HTTP ${resp.status}` : null,
	};
}

export { fazerLogin };
