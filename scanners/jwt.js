// Scanner de JWT — Fase 3
// Bate no /login, extrai o access token, quebra em partes, decodifica
// Base64URL manualmente (sem lib de JWT) e valida as claims mais importantes.
//
// Peças exportadas:
//   - decodificarBase64Url(str) → decodifica UMA parte do token
//   - quebrarJWT(token)         → { header, payload, assinaturaB64 }
//   - auditarJWT(alvo, motor)   → função orquestradora (roda todos os testes)

import { coletarResposta } from '../utils/http.js';

/**
 * Base64URL é Base64 padrão com duas trocas + padding opcional:
 *   '+' → '-'  (porque '+' em URL vira espaço)
 *   '/' → '_'  (porque '/' em URL é separador de path)
 *   '='  omitido (porque '=' em URL exige encoding)
 *
 * Pra decodificar, a gente reverte essas trocas e recompõe o padding
 * antes de passar pro Buffer, que só entende Base64 padrão.
 */
function decodificarBase64Url(str) {
	// 1. Reverte as substituições URL-safe
	let base64 = str.replace(/-/g, '+').replace(/_/g, '/');

	// 2. Recompõe o padding. Base64 exige comprimento múltiplo de 4:
	//    resto 2 → precisa de 2 '='
	//    resto 3 → precisa de 1 '='
	//    resto 0 → já está OK
	//    resto 1 → string inválida (não existe Base64 com esse tamanho)
	const resto = base64.length % 4;
	if (resto === 2) base64 += '==';
	else if (resto === 3) base64 += '=';
	else if (resto === 1) throw new Error('Base64URL malformada');

	// 3. Decodifica usando o Buffer do Node
	return Buffer.from(base64, 'base64').toString('utf-8');
}

/**
 * Quebra um JWT em suas 3 partes usando .split('.') — literal.
 * Decodifica header e payload (que são JSON) e devolve a assinatura crua.
 */
function quebrarJWT(token) {
	const partes = token.split('.');
	if (partes.length !== 3) {
		throw new Error(`Token deveria ter 3 partes, tem ${partes.length}`);
	}

	const [headerB64, payloadB64, assinaturaB64] = partes;


	const header = JSON.parse(decodificarBase64Url(headerB64));
	const payload = JSON.parse(decodificarBase64Url(payloadB64));

	return { header, payload, assinaturaB64 };
}

/**
 * Auditoria completa de JWT: 1 requisição no /login, extrai o token,
 * quebra em pedaços, e roda vários testes em cima do que veio.
 */
async function auditarJWT(alvo, motor) {
	// ─── 1. Login pra pegar o token ─────────────────────────
	let resposta;
	try {
		resposta = await coletarResposta(alvo.baseUrl + alvo.rotas.login, {
			metodo: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify(alvo.credenciais),
		});
	} catch (erro) {
		motor.registrar({
			id: 'jwt-login-inatingivel',
			categoria: 'jwt',
			descricao: 'Consegui chamar /login pra pegar o token',
			gravidade: 'critica',
			passou: false,
			detalhes: erro.message,
		});
		return;
	}

	// ─── 2. Body é JSON válido? ─────────────────────────────
	let body;
	try {
		body = JSON.parse(resposta.corpo);
	} catch {
		motor.registrar({
			id: 'jwt-body-json',
			categoria: 'jwt',
			descricao: '/login devolve JSON válido',
			gravidade: 'alta',
			passou: false,
			detalhes: `Body não é JSON: ${resposta.corpo.slice(0, 80)}`,
		});
		return;
	}

	// ─── 3. Achou um token no body? ─────────────────────────
	// Aceito nomes comuns: accessToken, access_token, token.
	const token = body.accessToken || body.access_token || body.token;
	if (!token || typeof token !== 'string') {
		motor.registrar({
			id: 'jwt-nao-encontrado',
			categoria: 'jwt',
			descricao: '/login devolve accessToken no body',
			gravidade: 'critica',
			passou: false,
			detalhes: 'Nenhum campo accessToken/access_token/token na resposta.',
		});
		return;
	}

	// ─── 4. Token tem formato JWT (3 partes, decodifica)? ───
	let quebrado;
	try {
		quebrado = quebrarJWT(token);
	} catch (erro) {
		motor.registrar({
			id: 'jwt-formato',
			categoria: 'jwt',
			descricao: 'Token tem formato JWT válido (3 partes Base64URL)',
			gravidade: 'critica',
			passou: false,
			detalhes: `${erro.message}. Token recebido: ${token.slice(0, 40)}...`,
		});
		return;
	}

	motor.registrar({
		id: 'jwt-formato',
		categoria: 'jwt',
		descricao: 'Token tem formato JWT válido',
		gravidade: 'alta',
		passou: true,
	});

	const { header, payload } = quebrado;

	// ─── 5. Algoritmo é seguro? ─────────────────────────────
	// alg: 'none' = bomba nuclear. Qualquer um forja tokens sem chave.
	const algSeguro = header.alg && header.alg.toLowerCase() !== 'none';
	motor.registrar({
		id: 'jwt-alg-none',
		categoria: 'jwt',
		descricao: `Algoritmo do token não é "none" (declara "${header.alg}")`,
		gravidade: 'critica',
		passou: algSeguro,
		detalhes: algSeguro
			? undefined
			: 'Header alg="none". Se o servidor aceitar, qualquer atacante forja tokens sem chave.',
	});

	// ─── 6. Claim exp presente? ─────────────────────────────
	const temExp = typeof payload.exp === 'number';
	motor.registrar({
		id: 'jwt-exp-presente',
		categoria: 'jwt',
		descricao: 'Token tem claim exp (data de expiração)',
		gravidade: 'alta',
		passou: temExp,
		detalhes: temExp
			? undefined
			: 'Sem exp, o token vale pra sempre. Se roubarem, roubaram pra vida.',
	});

	// ─── 7. Duração do token é razoável? ────────────────────
	// exp e iat são timestamps em SEGUNDOS (Unix epoch), não milissegundos.
	if (temExp && typeof payload.iat === 'number') {
		const duracaoSeg = payload.exp - payload.iat;
		const duracaoHoras = duracaoSeg / 3600;
		const duracaoDias = duracaoHoras / 24;
		const razoavel = duracaoHoras <= 24;

		const legivel = duracaoHoras < 24
			? `${duracaoHoras.toFixed(1)}h`
			: `${duracaoDias.toFixed(0)} dias`;

		motor.registrar({
			id: 'jwt-exp-duracao',
			categoria: 'jwt',
			descricao: `Access token dura no máximo 24h (dura ${legivel})`,
			gravidade: 'alta',
			passou: razoavel,
			detalhes: razoavel
				? undefined
				: `Access token válido por ${legivel}. Se roubarem, atacante tem esse tempo todo. Recomendado: 15-60 minutos, com refresh token pra estender.`,
		});
	}

	// ─── 8. Token já expirou? ───────────────────────────────
	if (temExp) {
		const agora = Math.floor(Date.now() / 1000);
		const expirado = payload.exp < agora;
		motor.registrar({
			id: 'jwt-exp-valido',
			categoria: 'jwt',
			descricao: 'Token recém-emitido ainda não está expirado',
			gravidade: 'media',
			passou: !expirado,
			detalhes: expirado
				? `Token expirou há ${agora - payload.exp}s. Login retornou token vencido — bug do servidor.`
				: undefined,
		});
	}

	// ─── 9. Claim iat presente? ─────────────────────────────
	motor.registrar({
		id: 'jwt-iat',
		categoria: 'jwt',
		descricao: 'Token tem claim iat (issued at)',
		gravidade: 'baixa',
		passou: typeof payload.iat === 'number',
		detalhes: typeof payload.iat === 'number'
			? undefined
			: 'Sem iat, não dá pra medir a idade do token.',
	});

	// ─── 10. Claims iss e aud (recomendação de boas práticas) ─
	// iss = quem emitiu, aud = pra quem se destina. Ausência não é falha
	// crítica, mas é indicador de maturidade do sistema.
	motor.registrar({
		id: 'jwt-iss',
		categoria: 'jwt',
		descricao: 'Token tem claim iss (issuer)',
		gravidade: 'baixa',
		passou: !!payload.iss,
		detalhes: payload.iss
			? undefined
			: 'Sem iss, servidores múltiplos que compartilham chave não sabem quem emitiu o token.',
	});

	motor.registrar({
		id: 'jwt-aud',
		categoria: 'jwt',
		descricao: 'Token tem claim aud (audience)',
		gravidade: 'baixa',
		passou: !!payload.aud,
		detalhes: payload.aud
			? undefined
			: 'Sem aud, um token emitido pra API A poderia ser aceito pela API B se compartilharem chave.',
	});
}

export { auditarJWT, quebrarJWT, decodificarBase64Url };
