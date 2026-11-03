// Scanner de AUTORIZAÇÃO — testa se o Bearer token é realmente validado
// na rota protegida. Três cenários:
//   1. Sem Authorization → servidor deve recusar (401/403)
//   2. Bearer VÁLIDO → servidor deve aceitar (2xx)
//   3. Bearer ADULTERADO (assinatura trocada) → servidor deve recusar (401)
//
// Isso prova que:
//   - Rota não é acidentalmente pública
//   - JwtBearer middleware ESTÁ ativo
//   - JwtBearer realmente VALIDA a assinatura (não só decoda)

import { coletarResposta } from '../utils/http.js';
import { fazerLogin } from '../utils/login.js';

async function auditarAutorizacao(alvo, motor) {
	const urlProtegida = alvo.baseUrl + alvo.rotas.protegida;

	// ─── Loga pra ter um token válido ─────────────────────────
	let sessao;
	try {
		sessao = await fazerLogin(alvo);
	} catch (erro) {
		motor.registrar({
			id: 'autz-preparacao',
			categoria: 'autorizacao',
			descricao: 'Login prévio pra pegar token de teste',
			gravidade: 'critica',
			passou: false,
			detalhes: erro.message,
		});
		return;
	}
	if (!sessao.accessToken) return;

	// ─── Teste 1: sem Authorization → deve recusar ────────────
	const semAuth = await coletarResposta(urlProtegida, {
		metodo: 'GET',
		headersPadrao: alvo.headersPadrao,
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
			: `⚠️ Rota protegida devolveu ${semAuth.status} SEM Bearer. Pode estar PÚBLICA sem querer.`,
	});

	// ─── Teste 2: Bearer válido → deve aceitar ────────────────
	const comAuth = await coletarResposta(urlProtegida, {
		metodo: 'GET',
		headers: { authorization: `Bearer ${sessao.accessToken}` },
		headersPadrao: alvo.headersPadrao,
	});
	const aceitaValido = comAuth.status >= 200 && comAuth.status < 300;
	motor.registrar({
		id: 'autz-com-token-valido',
		categoria: 'autorizacao',
		descricao: `Rota protegida aceita Bearer válido (recebeu ${comAuth.status})`,
		gravidade: 'alta',
		passou: aceitaValido,
		detalhes: aceitaValido
			? undefined
			: `Rota devolveu ${comAuth.status} mesmo com Bearer válido. Pode ser scope insuficiente (nosso token tem scope "setup") ou outra proteção (ex: HMAC request signing).`,
	});

	// ─── Teste 3: Bearer ADULTERADO → deve recusar ────────────
	// Pega o JWT real e flipa 1 caractere da assinatura. Se o servidor
	// VERIFICA a assinatura, não vai bater e devolve 401.
	// Se o servidor só DECODIFICA (bug clássico), aceita a adulteração.
	const partes = sessao.accessToken.split('.');
	const assinaturaAdulterada =
		partes[2].slice(0, -1) + (partes[2].slice(-1) === 'A' ? 'B' : 'A');
	const tokenAdulterado = `${partes[0]}.${partes[1]}.${assinaturaAdulterada}`;

	const comAuthRuim = await coletarResposta(urlProtegida, {
		metodo: 'GET',
		headers: { authorization: `Bearer ${tokenAdulterado}` },
		headersPadrao: alvo.headersPadrao,
	});
	const rejeitaAdulterado = comAuthRuim.status === 401 || comAuthRuim.status === 403;
	motor.registrar({
		id: 'autz-token-adulterado',
		categoria: 'autorizacao',
		descricao: `Rota protegida REJEITA token com assinatura adulterada (recebeu ${comAuthRuim.status})`,
		gravidade: 'critica',
		passou: rejeitaAdulterado,
		detalhes: rejeitaAdulterado
			? undefined
			: `⚠️ VULNERÁVEL: servidor aceitou token com assinatura inválida (status ${comAuthRuim.status}). Está só decodificando o JWT, não validando. Qualquer um forja tokens.`,
	});
}

export { auditarAutorizacao };
