// Scanner de SESSÃO — adaptado ao fluxo da API EV3.
//
// A API da empresa faz refresh via body JSON (não cookie), e exige:
//   POST /venia/reficite
//     Headers: Authorization: Bearer <jwt-antigo>
//     Body:    { refreshToken, Email, Imei }
//   Resposta: { accessToken, refreshToken, sessionHmacSecret, expiresIn }
//
// Testes:
//   1. /refresh funciona com credenciais válidas → 200 e novo par
//   2. ROTAÇÃO: reusar o refresh antigo → deve dar 401
//   3. REVOGAÇÃO: após /logout, usar o refresh → deve dar 401

import { coletarResposta } from '../utils/http.js';
import { fazerLogin } from '../utils/login.js';

/**
 * Faz login e devolve { accessToken, refreshToken }, ou lança erro.
 */
async function logar(alvo) {
	const r = await fazerLogin(alvo);
	if (r.erro) {
		throw new Error(`${r.erro}: ${r.corpo.slice(0, 200)}`);
	}
	return { accessToken: r.accessToken, refreshToken: r.refreshToken };
}

/**
 * Chama /refresh (POST body) e devolve a resposta bruta pra o chamador
 * poder examinar status + body.
 */
async function chamarRefresh(alvo, accessToken, refreshToken) {
	return coletarResposta(alvo.baseUrl + alvo.rotas.refresh, {
		metodo: 'POST',
		headers: {
			'content-type': 'application/json',
			authorization: `Bearer ${accessToken}`,
		},
		headersPadrao: alvo.headersPadrao,
		body: JSON.stringify({
			refreshToken,
			Email: alvo.emailParaRefresh || '',
			Imei: alvo.loginPayload?.imei || '',
		}),
	});
}

async function chamarLogout(alvo, accessToken) {
	return coletarResposta(alvo.baseUrl + alvo.rotas.logout, {
		metodo: 'POST',
		headers: {
			'content-type': 'application/json',
			authorization: `Bearer ${accessToken}`,
		},
		headersPadrao: alvo.headersPadrao,
	});
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

	if (!sessao.refreshToken) {
		// A API pode intencionalmente não emitir refresh em alguns scopes
		// (ex: scope "setup" só serve pra configurar PDV, exige novo login
		// depois). Marcamos como informativo, não como falha crítica.
		motor.registrar({
			id: 'sessao-refresh-presente',
			categoria: 'sessao',
			descricao: 'Login retornou refreshToken (fluxo de refresh disponível)',
			gravidade: 'baixa',
			passou: false,
			detalhes:
				'Login devolveu refreshToken=null. Pode ser por design (ex: scope "setup" exige re-login) ou falha. Verifique o scope do JWT recebido.',
		});
		return;
	}

	// ─── Teste 1: /refresh funciona ───────────────────────────
	let resp1;
	try {
		resp1 = await chamarRefresh(alvo, sessao.accessToken, sessao.refreshToken);
	} catch (erro) {
		motor.registrar({
			id: 'sessao-refresh-funciona',
			categoria: 'sessao',
			descricao: '/refresh troca refreshToken por novo access',
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
		descricao: `/refresh com credenciais válidas retorna 2xx (recebeu ${resp1.status})`,
		gravidade: 'alta',
		passou: refreshFuncionou,
		detalhes: refreshFuncionou
			? undefined
			: `Status ${resp1.status}. Body: ${resp1.corpo.slice(0, 200)}`,
	});

	if (!refreshFuncionou) return;

	// ─── Teste 2: Rotação ─────────────────────────────────────
	// Chama /refresh de novo com o refresh ANTIGO (não o que veio no passo 1).
	// Se o servidor rotaciona corretamente, o antigo foi invalidado.
	let resp2;
	try {
		resp2 = await chamarRefresh(alvo, sessao.accessToken, sessao.refreshToken);
	} catch (erro) {
		motor.registrar({
			id: 'sessao-refresh-rotacao',
			categoria: 'sessao',
			descricao: 'Refresh antigo é rejeitado (rotação)',
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
		descricao: `Refresh antigo reusado é rejeitado (recebeu ${resp2.status})`,
		gravidade: 'alta',
		passou: rotacionou,
		detalhes: rotacionou
			? undefined
			: `Refresh antigo aceito ${resp2.status} → SEM rotação. Se o refresh vazar, atacante usa até expirar.`,
	});

	// ─── Teste 3: Revogação após /logout ──────────────────────
	if (!alvo.rotas.logout) {
		return;
	}

	// Loga de novo (pra ter um par fresh)
	let sessao2;
	try {
		sessao2 = await logar(alvo);
	} catch {
		return;
	}

	// Chama /logout
	let respLogout;
	try {
		respLogout = await chamarLogout(alvo, sessao2.accessToken);
	} catch (erro) {
		motor.registrar({
			id: 'sessao-logout-revoga',
			categoria: 'sessao',
			descricao: 'Rota /logout respondeu',
			gravidade: 'media',
			passou: false,
			detalhes: `/logout inacessível: ${erro.message}`,
		});
		return;
	}

	// Mesmo que /logout dê 404 (não existe no backend), testamos o comportamento:
	// o refresh deveria ser invalidado. Se continua funcionando → vulnerabilidade.
	let respPosLogout;
	try {
		respPosLogout = await chamarRefresh(alvo, sessao2.accessToken, sessao2.refreshToken);
	} catch (erro) {
		motor.registrar({
			id: 'sessao-logout-revoga',
			categoria: 'sessao',
			descricao: 'Refresh após /logout é rejeitado',
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
		descricao: `Refresh após logout devolve 401 (recebeu ${respPosLogout.status}, logout respondeu ${respLogout.status})`,
		gravidade: 'media',
		passou: revogou,
		detalhes: revogou
			? undefined
			: `Logout NÃO invalidou o refresh (status ${respPosLogout.status}). Usuário "sai da conta" mas token roubado continua ativo.`,
	});
}

export { auditarSessao };
