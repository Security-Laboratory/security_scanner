// Scanner de COOKIES — Fase 2, Passo 2.3
// Loga na rota /login, lê os Set-Cookie que voltam e verifica se cada cookie
// carrega os atributos de segurança: HttpOnly, Secure, SameSite.

import { coletarResposta } from '../utils/http.js';

/**
 * Parseia uma string de Set-Cookie no formato:
 *   "refresh_token=abc123; Path=/; HttpOnly; Secure; SameSite=Strict"
 * e devolve um objeto normalizado.
 */
function parsearCookie(setCookieStr) {
	const partes = setCookieStr.split(';').map((p) => p.trim());

	// Primeira parte é sempre "nome=valor"
	const [nome, ...restoValor] = partes[0].split('=');
	const valor = restoValor.join('='); // valor pode ter '=' dentro (base64, JWT)

	// Resto são atributos: alguns booleanos (HttpOnly), outros chave=valor (SameSite=Lax)
	const atributos = {};
	for (const parte of partes.slice(1)) {
		const [chave, ...v] = parte.split('=');
		atributos[chave.toLowerCase()] = v.length ? v.join('=') : true;
	}

	return {
		nome,
		valor,
		httpOnly: atributos['httponly'] === true,
		secure: atributos['secure'] === true,
		sameSite:
			typeof atributos['samesite'] === 'string' ? atributos['samesite'] : null,
		maxAge: atributos['max-age'] || null,
		path: atributos['path'] || null,
	};
}

/**
 * Auditoria de cookies: bate no /login com credenciais válidas e analisa
 * cada Set-Cookie que voltar.
 */
async function auditarCookies(alvo, motor) {
	const urlLogin = alvo.baseUrl + alvo.rotas.login;

	let resposta;
	try {
		resposta = await coletarResposta(urlLogin, {
			metodo: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify(alvo.credenciais),
		});
	} catch (erro) {
		motor.registrar({
			id: 'cookies-login-inatingivel',
			categoria: 'cookies',
			descricao: 'Rota de login respondeu',
			gravidade: 'critica',
			passou: false,
			detalhes: `Não consegui chamar ${urlLogin}: ${erro.message}`,
		});
		return;
	}

	// ─── Verifica se o login funcionou ─────────────────────────────
	// Sem login bem sucedido, não tem cookie pra analisar.
	const loginOk = resposta.status >= 200 && resposta.status < 300;
	motor.registrar({
		id: 'cookies-login-status',
		categoria: 'cookies',
		descricao: `Login com credenciais válidas retornou 2xx (recebeu ${resposta.status})`,
		gravidade: 'alta',
		passou: loginOk,
		detalhes: loginOk
			? undefined
			: `Login devolveu ${resposta.status}. Confira credenciais em config.js.`,
	});
	if (!loginOk) return;

	// ─── O login devolveu algum cookie? ────────────────────────────
	if (resposta.setCookies.length === 0) {
		motor.registrar({
			id: 'cookies-nenhum',
			categoria: 'cookies',
			descricao: 'Login retornou pelo menos um Set-Cookie',
			gravidade: 'media',
			passou: false,
			detalhes:
				'Nenhum Set-Cookie na resposta. Se você usa refresh token, ele DEVE vir em cookie HttpOnly, não em JSON.',
		});
		return;
	}

	// Pra ver os cookies destrinchados sem poluir o output do scanner,
	// rode: npm run cookies

	// ─── Pra CADA cookie, verifica os 3 atributos de segurança ────
	for (const cookieStr of resposta.setCookies) {
		const c = parsearCookie(cookieStr);

		// HttpOnly — invisível pro JavaScript. Bloqueia roubo por XSS.
		motor.registrar({
			id: `cookies-httponly-${c.nome}`,
			categoria: 'cookies',
			descricao: `Cookie "${c.nome}" com HttpOnly`,
			gravidade: 'alta',
			passou: c.httpOnly,
			detalhes: c.httpOnly
				? undefined
				: `Cookie "${c.nome}" acessível via document.cookie. XSS lê e envia pro atacante.`,
		});

		// Secure — só trafega em HTTPS. Bloqueia sniffing em rede pública.
		motor.registrar({
			id: `cookies-secure-${c.nome}`,
			categoria: 'cookies',
			descricao: `Cookie "${c.nome}" com Secure`,
			gravidade: 'alta',
			passou: c.secure,
			detalhes: c.secure
				? undefined
				: `Cookie "${c.nome}" viaja em HTTP puro. Atacante em Wi-Fi público captura.`,
		});

		// SameSite — precisa ser Strict ou Lax. None é praticamente "sem SameSite".
		const sameSiteValido =
			c.sameSite && ['strict', 'lax'].includes(c.sameSite.toLowerCase());
		motor.registrar({
			id: `cookies-samesite-${c.nome}`,
			categoria: 'cookies',
			descricao: `Cookie "${c.nome}" com SameSite (Strict ou Lax)`,
			gravidade: 'media',
			passou: sameSiteValido,
			detalhes: sameSiteValido
				? undefined
				: `Cookie "${c.nome}" sem SameSite adequado (valor atual: ${c.sameSite || 'ausente'}). Vulnerável a CSRF.`,
		});
	}
}

export { auditarCookies, parsearCookie };
