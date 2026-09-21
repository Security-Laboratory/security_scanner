// Textos de "como corrigir" pra cada tipo de achado.
// Separado da lógica dos scanners porque é conteúdo — muda com frequência
// e não faz sentido misturar com código de teste.
//
// A busca aceita ID exato OU um prefixo (útil pra IDs dinâmicos tipo
// "cookies-httponly-refresh_token" → cai em "cookies-httponly").

const REMEDIACOES = {
	// ─── REDE ────────────────────────────────────────────────────────
	'rede-https':
		'Configure HTTPS no servidor com certificado válido (Let\'s Encrypt é gratuito). Redirecione HTTP → HTTPS com status 301. Nunca aceite requisições HTTP em produção.',

	'rede-conectividade':
		'Servidor devolveu erro 5xx. Verifique logs do backend e do proxy reverso (nginx/CloudFront). Um scanner de segurança não substitui um monitor de disponibilidade.',

	'rede-x-powered-by':
		'No Express, adicione `app.disable(\'x-powered-by\')` logo após criar o app. Em nginx, defina `server_tokens off;`. Não revele a stack; isso reduz superfície de ataque direcionado.',

	'rede-server-header':
		'Configure o proxy reverso (nginx/Apache) para omitir ou generalizar o header `Server`. Não revele versão exata da stack.',

	'rede-hsts':
		'Adicione o header `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` em todas as respostas HTTPS. Impede downgrade forçado por atacantes na rede.',

	'rede-csp':
		'Defina uma Content-Security-Policy restritiva. Comece com `default-src \'self\'` e adicione origens conforme necessário. Bloqueia execução de scripts injetados por XSS.',

	// ─── COOKIES ─────────────────────────────────────────────────────
	'cookies-login-status':
		'A rota de login deve devolver 2xx com credenciais válidas. Se está devolvendo 4xx/5xx, verifique o handler.',

	'cookies-login-inatingivel':
		'Confirme que o servidor está no ar na URL configurada. Verifique firewall, DNS e o caminho da rota de login.',

	'cookies-nenhum':
		'Se você usa refresh token, envie-o via cookie `HttpOnly` no `Set-Cookie`. Nunca coloque refresh token no body JSON — JS malicioso via XSS lê o body.',

	'cookies-httponly':
		'No Express: `res.cookie(\'nome\', valor, { httpOnly: true, ... })`. O atributo `HttpOnly` impede `document.cookie` de ler — bloqueia roubo por XSS.',

	'cookies-secure':
		'No Express: `res.cookie(\'nome\', valor, { secure: true, ... })`. Faz o navegador só enviar o cookie em HTTPS. Sem isso, cookie vaza em Wi-Fi público.',

	'cookies-samesite':
		'No Express: `res.cookie(\'nome\', valor, { sameSite: \'strict\', ... })`. Use `strict` sempre que possível; `lax` para fluxos com redirect de terceiros; NUNCA `none` sem `secure`.',

	// ─── JWT ─────────────────────────────────────────────────────────
	'jwt-login-inatingivel':
		'Rota de login está inacessível. Verifique servidor e URL antes de tudo.',

	'jwt-body-json':
		'A rota de login deve devolver JSON válido com Content-Type: application/json. Verifique se está usando `res.json(...)`, não `res.send(string)`.',

	'jwt-nao-encontrado':
		'A rota de login deve devolver o access token num campo `accessToken`, `access_token` ou `token` no JSON.',

	'jwt-formato':
		'Token não segue formato JWT (3 partes separadas por ponto, cada parte em Base64URL). Verifique como o token é gerado.',

	'jwt-alg-none':
		'CRÍTICO: nunca aceite `alg: none`. Sempre passe `algorithms: [\'HS256\']` (ou o algoritmo específico) para `jwt.verify()`. Sem essa restrição, atacante forja tokens sem chave.',

	'jwt-exp-presente':
		'Sempre inclua a claim `exp` ao emitir tokens: `jwt.sign(payload, secret, { expiresIn: \'15m\' })`. Token sem `exp` vale para sempre.',

	'jwt-exp-duracao':
		'Access token deve durar entre 15 e 60 minutos. Para sessões longas, use refresh token com rotação. Access longo = janela grande de ataque se vazar.',

	'jwt-exp-valido':
		'Servidor emitiu token já expirado — bug na configuração de `expiresIn` ou relógio dessincronizado.',

	'jwt-iat':
		'Inclua `iat` (issued at) — a lib `jsonwebtoken` adiciona automaticamente. Útil pra auditar idade do token e implementar revogação por horário.',

	'jwt-iss':
		'Adicione `iss` (issuer) no payload: `{ iss: \'sua-api.com\' }`. Facilita rastrear qual serviço emitiu, especialmente em arquiteturas com múltiplas APIs.',

	'jwt-aud':
		'Adicione `aud` (audience) no payload: `{ aud: \'sua-api\' }` e valide com `jwt.verify(token, secret, { audience: \'sua-api\' })`. Impede que um token emitido pra API A seja aceito pela API B.',

	// ─── ATAQUES ─────────────────────────────────────────────────────
	'ataque-none-preparacao':
		'Não foi possível pegar um token válido pra montar o ataque. Verifique credenciais e rota de login.',

	'ataque-none-execucao':
		'Ataque não pôde ser disparado — rota protegida inacessível. Verifique conectividade.',

	'ataque-alg-none':
		'CRÍTICO: seu servidor aceita tokens com `alg: none` sem verificar assinatura. Correção: sempre passe `algorithms: [\'HS256\']` (ou específico) ao `jwt.verify()`. Bloqueia forja de tokens.',

	'ataque-brute-preparacao':
		'Não foi possível pegar um token pra rodar brute-force. Verifique credenciais.',

	'ataque-brute-hmac':
		'CRÍTICO: chave HMAC descoberta por wordlist. Use chave aleatória de 32+ bytes: `openssl rand -base64 32`. Armazene em variável de ambiente, nunca no código.',
};

/**
 * Retorna a remediação pra um ID de achado. Tenta exato primeiro,
 * depois prefixo (útil pra IDs com nome dinâmico anexado no fim).
 */
function obterRemediacao(id) {
	if (REMEDIACOES[id]) return REMEDIACOES[id];
	for (const chave of Object.keys(REMEDIACOES)) {
		if (id.startsWith(chave + '-')) return REMEDIACOES[chave];
	}
	return null;
}

export { REMEDIACOES, obterRemediacao };
