// Helper único de login — centraliza a complexidade de montar o header
// Basic Auth + body JSON do payload de login. Usado por todos os scanners
// que precisam de um accessToken pra testar.

import { coletarResposta } from './http.js';
import { montarBasic } from './auth.js';

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

	return {
		status: resp.status,
		corpo: resp.corpo,
		setCookies: resp.setCookies,
		accessToken: respBody.accessToken || respBody.access_token || respBody.token || null,
		refreshToken: respBody.refreshToken || respBody.refresh_token || null,
		sessionHmacSecret: respBody.sessionHmacSecret || null,
		expiresIn: respBody.expiresIn || null,
		erro: resp.status >= 400 ? `HTTP ${resp.status}` : null,
	};
}

export { fazerLogin };
