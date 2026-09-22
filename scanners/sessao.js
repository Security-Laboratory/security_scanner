// Scanner de SESSÃO — Fase 5 (expansão)
// Testa o ciclo completo: login → refresh → refresh de novo (rotação?) → logout → refresh (revogado?)
//
// Um scanner de auth sem esses testes é meia-boca — a maior parte dos vazamentos
// em produção acontece por refresh eterno ou logout que não invalida nada.

import { coletarResposta } from '../utils/http.js';

/**
 * Extrai o valor de refresh_token da lista de Set-Cookie.
 * Devolve null se não encontrar.
 */
function extrairRefreshDosSetCookies(setCookies) {
	for (const linha of setCookies) {
		const match = linha.match(/refresh_token=([^;]+)/);
		if (match) return match[1];
	}
	return null;
}

/**
 * Faz login e devolve { accessToken, cookieHeader }.
 * cookieHeader já vem no formato pronto pra reenviar no header Cookie.
 */
async function logar(alvo) {
	const resp = await coletarResposta(alvo.baseUrl + alvo.rotas.login, {
		metodo: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify(alvo.credenciais),
	});
	const body = JSON.parse(resp.corpo);
	const refresh = extrairRefreshDosSetCookies(resp.setCookies);
	return {
		accessToken: body.accessToken || body.access_token || body.token,
		cookieHeader: refresh ? `refresh_token=${refresh}` : '',
	};
}

/**
 * Auditoria completa de sessão.
 */
async function auditarSessao(alvo, motor) {
	// ─── Preparação: loga pra pegar o par inicial ─────────────
	let sessao;
	try {
		sessao = await logar(alvo);
	} catch (erro) {
		motor.registrar({
			id: 'sessao-preparacao',
			categoria: 'sessao',
			descricao: 'Login inicial (pra testes de sessão)',
			gravidade: 'critica',
			passou: false,
			detalhes: erro.message,
		});
		return;
	}

	if (!sessao.cookieHeader) {
		motor.registrar({
			id: 'sessao-refresh-cookie',
			categoria: 'sessao',
			descricao: 'Login retornou cookie refresh_token',
			gravidade: 'alta',
			passou: false,
			detalhes: 'Sem cookie refresh_token no /login — não dá pra testar refresh flow.',
		});
		return;
	}

	// ─── Teste 1: /refresh funciona com cookie válido ─────────
	let resp1;
	try {
		resp1 = await coletarResposta(alvo.baseUrl + alvo.rotas.refresh, {
			metodo: 'POST',
			headers: { cookie: sessao.cookieHeader },
		});
	} catch (erro) {
		motor.registrar({
			id: 'sessao-refresh-funciona',
			categoria: 'sessao',
			descricao: '/refresh troca o cookie por novo access token',
			gravidade: 'alta',
			passou: false,
			detalhes: erro.message,
		});
		return;
	}

	const refreshFuncionou = resp1.status >= 200 && resp1.status < 300;
	motor.registrar({
		id: 'sessao-refresh-funciona',
		categoria: 'sessao',
		descricao: `/refresh com cookie válido retorna 2xx (recebeu ${resp1.status})`,
		gravidade: 'alta',
		passou: refreshFuncionou,
		detalhes: refreshFuncionou
			? undefined
			: `Cookie válido, mas /refresh devolveu ${resp1.status}. Fluxo de refresh quebrado.`,
	});

	if (!refreshFuncionou) return;

	// ─── Teste 2: rotação do refresh token ────────────────────
	// Chama /refresh de novo com o MESMO cookie antigo.
	// Se o servidor rotaciona, o antigo foi invalidado → 401.
	// Se aceita → refresh eterno, vulnerabilidade média.
	let resp2;
	try {
		resp2 = await coletarResposta(alvo.baseUrl + alvo.rotas.refresh, {
			metodo: 'POST',
			headers: { cookie: sessao.cookieHeader }, // mesmo cookie antigo!
		});
	} catch (erro) {
		motor.registrar({
			id: 'sessao-refresh-rotacao',
			categoria: 'sessao',
			descricao: 'Segundo uso do refresh antigo é rejeitado (rotação)',
			gravidade: 'alta',
			passou: false,
			detalhes: erro.message,
		});
		return;
	}

	const rotacionou = resp2.status === 401 || resp2.status === 403;
	motor.registrar({
		id: 'sessao-refresh-rotacao',
		categoria: 'sessao',
		descricao: `Refresh antigo, reusado, é rejeitado (recebeu ${resp2.status})`,
		gravidade: 'alta',
		passou: rotacionou,
		detalhes: rotacionou
			? undefined
			: `Refresh antigo aceito ${resp2.status} → sem rotação. Se vazar, atacante usa até expirar.`,
	});

	// ─── Teste 3: revogação após logout ───────────────────────
	// Loga de novo (pra ter um refresh fresh), chama /logout, tenta /refresh, espera 401.
	if (!alvo.rotas.logout) {
		motor.registrar({
			id: 'sessao-logout-revoga',
			categoria: 'sessao',
			descricao: 'Rota /logout existe e revoga refresh',
			gravidade: 'media',
			passou: false,
			detalhes: 'Nenhuma rota de logout definida em config.rotas.logout.',
		});
		return;
	}

	let sessao2;
	try {
		sessao2 = await logar(alvo);
	} catch {
		return; // sem sessão nova não dá pra testar
	}

	try {
		await coletarResposta(alvo.baseUrl + alvo.rotas.logout, {
			metodo: 'POST',
			headers: { cookie: sessao2.cookieHeader },
		});
	} catch (erro) {
		motor.registrar({
			id: 'sessao-logout-revoga',
			categoria: 'sessao',
			descricao: 'Logout responde (mesmo que sem invalidar)',
			gravidade: 'media',
			passou: false,
			detalhes: `/logout inacessível: ${erro.message}`,
		});
		return;
	}

	// Depois do logout, tenta usar o refresh — deveria dar 401
	let respPosLogout;
	try {
		respPosLogout = await coletarResposta(alvo.baseUrl + alvo.rotas.refresh, {
			metodo: 'POST',
			headers: { cookie: sessao2.cookieHeader },
		});
	} catch (erro) {
		motor.registrar({
			id: 'sessao-logout-revoga',
			categoria: 'sessao',
			descricao: 'Refresh após logout é rejeitado',
			gravidade: 'media',
			passou: false,
			detalhes: erro.message,
		});
		return;
	}

	const revogou = respPosLogout.status === 401 || respPosLogout.status === 403;
	motor.registrar({
		id: 'sessao-logout-revoga',
		categoria: 'sessao',
		descricao: `Refresh após logout devolve 401 (recebeu ${respPosLogout.status})`,
		gravidade: 'media',
		passou: revogou,
		detalhes: revogou
			? undefined
			: `Logout NÃO invalidou o refresh (status ${respPosLogout.status}). Usuário sai da conta, mas token roubado continua ativo.`,
	});
}

export { auditarSessao };
