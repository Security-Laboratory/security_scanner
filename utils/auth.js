// Helpers de autenticação HTTP.
// Monta headers Authorization no formato correto pra Basic ou Bearer.

/**
 * Codifica usuario:senha em Base64 pra uso em HTTP Basic Auth.
 * NÃO é criptografia — é codificação reversível. Só use com HTTPS.
 */
function montarBasic(usuario, senha) {
	const credencial = Buffer.from(`${usuario}:${senha}`, 'utf-8').toString('base64');
	return `Basic ${credencial}`;
}

function montarBearer(token) {
	return `Bearer ${token}`;
}

/**
 * Decide qual Authorization usar pra uma rota baseado no catálogo + config.
 * Retorna uma string pronta pra ir no header, ou null se não houver.
 *
 * Prioridade:
 *   1. Se o grupo da rota tem requireBasic=true E a config tem basicAuth → Basic
 *   2. Se tem token Bearer disponível → Bearer
 *   3. null (sem auth)
 */
function obterAuthorization({ path, grupos, alvo, bearerToken }) {
	// Procura o grupo que contém esse path (primeiro match)
	const grupo = grupos.find((g) => g.paths.includes(path));

	if (grupo?.requireBasic && alvo.basicAuth?.usuario && alvo.basicAuth?.senha) {
		return montarBasic(alvo.basicAuth.usuario, alvo.basicAuth.senha);
	}

	if (bearerToken) {
		return montarBearer(bearerToken);
	}

	return null;
}

export { montarBasic, montarBearer, obterAuthorization };
