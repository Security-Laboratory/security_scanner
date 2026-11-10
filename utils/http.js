/**
 * Dispara uma requisição HTTP e devolve os dados brutos da resposta.
 * Não julga — só coleta.
 */
async function coletarResposta(url, opcoes = {}) {
  const metodo = opcoes.metodo || 'POST';
  const inicio = Date.now();

  // Mescla headers padrão (opcoes.headersPadrao) com os do request.
  // Headers do request têm prioridade — permite override pontual.
  const headersFinais = {
    ...(opcoes.headersPadrao || {}),
    ...(opcoes.headers || {}),
  };

  // Se `assinarComSegredo` foi passado, calcula HMAC do body e adiciona
  // os 3 headers X-Ev3-* exigidos pelo backend em rotas sensíveis.
  // Importado dinâmico pra evitar dependência circular (assinatura usa http).
  if (opcoes.assinarComSegredo) {
    const { assinarRequisicao } = await import('./assinatura.js');
    const sigHeaders = assinarRequisicao(opcoes.body || '', opcoes.assinarComSegredo);
    Object.assign(headersFinais, sigHeaders);
  }

  if (process.env.DEBUG_SIGN === '1') {
    console.log('[http] →', metodo, url);
    const headersSafe = {};
    for (const [k, v] of Object.entries(headersFinais)) {
      if (/^authorization$/i.test(k)) {
        headersSafe[k] = v.slice(0, 20) + '... (mascarado)';
      } else {
        headersSafe[k] = v;
      }
    }
    console.log('  headers:', JSON.stringify(headersSafe, null, 2));
    if (opcoes.body) console.log('  body:', opcoes.body);
  }

  const resposta = await fetch(url, {
    method: metodo,
    headers: headersFinais,
    body: opcoes.body,
    redirect: 'manual'  // não segue redirects — a gente quer VER o 301/302
  });

  if (process.env.DEBUG_SIGN === '1') {
    console.log('[http] ← status', resposta.status, resposta.statusText);
  }

  const duracao = Date.now() - inicio;

  const headers = {};
  for (const [nome, valor] of resposta.headers) {
    headers[nome] = valor;
  }

  // Set-Cookie merece tratamento à parte: um servidor pode mandar VÁRIOS Set-Cookie
  // e o iterator acima achata todos numa string única separada por vírgula — o que
  // quebra o parsing (datas de cookies contêm vírgula). O getSetCookie() devolve
  // um array com um cookie por posição, do jeito certo.
  const setCookies = typeof resposta.headers.getSetCookie === 'function'
    ? resposta.headers.getSetCookie()
    : [];

  let corpo = '';
  try {
    corpo = await resposta.text();
  } catch {
    // corpo continua '' (o default). Se resposta.text() estourar
    // — servidor cortou a conexão, corpo binário quebrado —
    // seguimos em frente; o scanner cuida das headers de qualquer jeito.
  }

  return {
    url,
    status: resposta.status,
    statusText: resposta.statusText,
    duracaoMs: duracao,
    headers,
    setCookies,
    corpo
  };
}

export { coletarResposta };
