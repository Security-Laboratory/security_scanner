// Scanner de AUTORIZAÇÃO — testa se o Bearer token é realmente validado
// na rota protegida.
//
// A rota /api/Empresa/ListarEmpresa é POST e exige:
//   - Authorization: Bearer <jwt>
//   - HMAC request signing (X-Ev3-Timestamp, X-Ev3-Nonce, X-Ev3-Signature)
//   - Body JSON: { emailUsuario: "..." }
//
// 3 cenários:
//   1. Sem Bearer, COM HMAC         → servidor deve recusar (401/403)
//   2. Bearer VÁLIDO + HMAC válido   → servidor deve aceitar (2xx)
//   3. Bearer ADULTERADO + HMAC OK  → servidor deve recusar (401)
//
// HMAC fixo em todos os testes pra ISOLAR o que a gente testa (autorização
// de Bearer, não de assinatura).

import { coletarResposta } from '../utils/http.js';
import { fazerLogin } from '../utils/login.js';

async function auditarAutorizacao(alvo, motor) {
	const urlProtegida = alvo.baseUrl + alvo.rotas.protegida;
	const corpo = typeof alvo.bodyProtegida === 'function' ? alvo.bodyProtegida() : '{}';

	// ─── Preparação: login pra obter JWT + sessionHmacSecret ───
	let sessao;
	try {
		sessao = await fazerLogin(alvo);
	} catch (erro) {
		motor.registrar({
			id: 'autz-preparacao',
			categoria: 'autorizacao',
			descricao: 'Login prévio pra pegar token + sessionHmacSecret',
			gravidade: 'critica',
			passou: false,
			detalhes: erro.message,
		});
		return;
	}
	if (!sessao.accessToken || !sessao.sessionHmacSecret) {
		motor.registrar({
			id: 'autz-preparacao',
			categoria: 'autorizacao',
			descricao: 'Login devolveu accessToken + sessionHmacSecret',
			gravidade: 'critica',
			passou: false,
			detalhes: 'Resposta de login não trouxe os campos necessários pra autorizar os testes seguintes.',
		});
		return;
	}

	// ─── Teste 1: sem Bearer (mas com HMAC válido) → deve recusar ───
	const semAuth = await coletarResposta(urlProtegida, {
		metodo: 'POST',
		headers: { 'content-type': 'application/json' },
		headersPadrao: alvo.headersPadrao,
		body: corpo,
		assinarComSegredo: sessao.sessionHmacSecret,
	});
	const bloqueiaSemToken = semAuth.status === 401 || semAuth.status === 403;
	motor.registrar({
		id: 'autz-sem-token',
		categoria: 'autorizacao',
		descricao: `Rota protegida rejeita requisição SEM Bearer (recebeu ${semAuth.status})`,
		gravidade: 'critica',
		passou: bloqueiaSemToken,
		detalhes: bloqueiaSemToken
			? undefined
			: `⚠️ Rota protegida devolveu ${semAuth.status} SEM Bearer — pode estar pública sem querer.`,
	});

	// ─── Teste 2: Bearer válido + HMAC válido → deve aceitar ──────
	const comAuth = await coletarResposta(urlProtegida, {
		metodo: 'POST',
		headers: {
			'content-type': 'application/json',
			authorization: `Bearer ${sessao.accessToken}`,
		},
		headersPadrao: alvo.headersPadrao,
		body: corpo,
		assinarComSegredo: sessao.sessionHmacSecret,
	});
	const aceitaValido = comAuth.status >= 200 && comAuth.status < 300;
	motor.registrar({
		id: 'autz-com-token-valido',
		categoria: 'autorizacao',
		descricao: `Rota protegida aceita Bearer + HMAC válidos (recebeu ${comAuth.status})`,
		gravidade: 'alta',
		passou: aceitaValido,
		detalhes: aceitaValido
			? undefined
			: `Rota devolveu ${comAuth.status}. Possíveis causas: (1) scope insuficiente (nosso token tem scope "setup"), (2) outra proteção customizada, (3) body esperado diferente de "${corpo}".`,
	});

	// ─── Teste 3: Bearer ADULTERADO + HMAC válido → deve recusar ──
	// Flipa 1 caractere da assinatura do JWT. HMAC do request continua OK.
	const partes = sessao.accessToken.split('.');
	const assinaturaAdulterada =
		partes[2].slice(0, -1) + (partes[2].slice(-1) === 'A' ? 'B' : 'A');
	const tokenAdulterado = `${partes[0]}.${partes[1]}.${assinaturaAdulterada}`;

	const comAuthRuim = await coletarResposta(urlProtegida, {
		metodo: 'POST',
		headers: {
			'content-type': 'application/json',
			authorization: `Bearer ${tokenAdulterado}`,
		},
		headersPadrao: alvo.headersPadrao,
		body: corpo,
		assinarComSegredo: sessao.sessionHmacSecret,
	});
	const rejeitaAdulterado = comAuthRuim.status === 401 || comAuthRuim.status === 403;
	// Diagnóstico sincero: só podemos afirmar "servidor VALIDA assinatura"
	// se o teste 2 passou (200). Se o 2 também deu 403, não dá pra distinguir.
	const diagnosticoConclusivo = aceitaValido;
	motor.registrar({
		id: 'autz-token-adulterado',
		categoria: 'autorizacao',
		descricao: diagnosticoConclusivo
			? `Rota REJEITA token com assinatura adulterada (recebeu ${comAuthRuim.status})`
			: `Rota rejeitou token adulterado (${comAuthRuim.status}), mas também rejeitou token válido — não conclusivo`,
		gravidade: 'critica',
		passou: rejeitaAdulterado && diagnosticoConclusivo,
		detalhes: !rejeitaAdulterado
			? `⚠️ VULNERÁVEL: servidor aceitou token com assinatura inválida (status ${comAuthRuim.status}).`
			: !diagnosticoConclusivo
				? 'Teste inconclusivo — o teste 2 (Bearer válido) precisa passar pra isolarmos.'
				: undefined,
	});
}

export { auditarAutorizacao };
