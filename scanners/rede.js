// Scanner de REDE — Fase 2 (Passos 2.1 e 2.2)
// Auditoria de camada de infraestrutura: HTTPS, headers de segurança, redirects.
//
// Arquitetura:
//   - coletarResposta(url) → função de baixo nível, dispara HTTP e devolve resposta bruta.
//   - auditarRede(alvo, motor) → função de alto nível, faz 1 requisição no alvo
//     e roda VÁRIOS testes em cima da mesma resposta.

import { coletarResposta } from '../utils/http.js';

/**
 * Auditoria completa de rede.
 * Faz 1 requisição no alvo e roda TODOS os testes de infra em cima dela.
 */
async function auditarRede(alvo, motor) {
	// ─── Teste 1: URL usa HTTPS? ─────────────────────────────
	// Não precisa nem de requisição — dá pra ver só olhando a string.
	const usaHttps = alvo.baseUrl.startsWith('https://');
	motor.registrar({
		id: 'rede-https',
		categoria: 'rede',
		descricao: 'Alvo usa HTTPS',
		gravidade: 'critica',
		passou: usaHttps,
		detalhes: usaHttps
			? undefined
			: `Alvo em ${alvo.baseUrl.split('://')[0]}://. Todo tráfego (incluindo tokens JWT) viaja em texto plano — qualquer um na mesma rede lê.`,
	});

	// ─── UMA requisição, todos os outros testes em cima dela ─────
	let resposta;
	try {
		resposta = await coletarResposta(alvo.baseUrl + alvo.rotas.protegida);
	} catch (erro) {
		// Servidor inatingível: registra 1 achado crítico e desiste dos demais.
		// Não faz sentido rodar "tem HSTS?" se nem o servidor responde.
		motor.registrar({
			id: 'rede-conectividade',
			categoria: 'rede',
			descricao: 'Não consegui contatar o servidor',
			gravidade: 'critica',
			passou: false,
			detalhes: `Erro: ${erro.message}. O alvo está no ar?`,
		});
		return;
	}

	// ─── Teste 2: Servidor respondeu (status < 500)? ─────────
	motor.registrar({
		id: 'rede-conectividade',
		categoria: 'rede',
		descricao: `Servidor respondeu em ${resposta.duracaoMs}ms (status ${resposta.status})`,
		gravidade: 'alta',
		passou: resposta.status < 500,
		detalhes:
			resposta.status >= 500
				? `Servidor devolveu erro ${resposta.status} ${resposta.statusText}`
				: undefined,
	});

	// ─── Teste 3: x-powered-by ausente? ──────────────────────
	// Esse header revela a stack ("Express", "PHP/7.4", "ASP.NET"). Ajuda o
	// atacante a mirar exploits específicos. Boa prática: remover.
	const poweredBy = resposta.headers['x-powered-by'];
	motor.registrar({
		id: 'rede-x-powered-by',
		categoria: 'rede',
		descricao: 'Header x-powered-by removido (não revela a stack)',
		gravidade: 'baixa',
		passou: !poweredBy,
		detalhes: poweredBy
			? `Servidor revela: "${poweredBy}". Facilita ataques direcionados.`
			: undefined,
	});

	// ─── Teste 4: Header server genérico ou ausente? ─────────
	// Mesma ideia do x-powered-by: pode revelar "nginx/1.18.0", "Apache/2.4.29".
	const serverHeader = resposta.headers['server'];
	motor.registrar({
		id: 'rede-server-header',
		categoria: 'rede',
		descricao: 'Header server ausente ou genérico',
		gravidade: 'baixa',
		passou: !serverHeader,
		detalhes: serverHeader ? `Servidor revela: "${serverHeader}"` : undefined,
	});

	// ─── Teste 5: HSTS (Strict-Transport-Security) ───────────
	// Só faz sentido se o alvo é HTTPS. HSTS avisa o navegador: "de hoje em
	// diante, só me acesse por HTTPS". Sem ele, atacante pode forçar downgrade
	// pra HTTP e capturar tudo.
	if (usaHttps) {
		const hsts = resposta.headers['strict-transport-security'];
		motor.registrar({
			id: 'rede-hsts',
			categoria: 'rede',
			descricao: 'Header Strict-Transport-Security presente',
			gravidade: 'media',
			passou: !!hsts,
			detalhes: hsts
				? undefined
				: 'Sem HSTS. Atacante pode forçar downgrade HTTPS → HTTP num MITM.',
		});
	}

	// ─── Teste 6: Content-Security-Policy presente? ──────────
	// Header defensivo contra XSS. Diz ao navegador "só carregue scripts destas
	// origens". Se você lembra do meu resumo: XSS lê localStorage/tokens.
	const csp = resposta.headers['content-security-policy'];
	motor.registrar({
		id: 'rede-csp',
		categoria: 'rede',
		descricao: 'Header Content-Security-Policy presente',
		gravidade: 'media',
		passou: !!csp,
		detalhes: csp
			? undefined
			: 'Sem CSP. Navegador não tem regra pra bloquear scripts de origens não confiáveis (defesa contra XSS).',
	});
}

export { auditarRede };
