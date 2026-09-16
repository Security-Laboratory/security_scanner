/**
 * Dispara uma requisição HTTP e devolve os dados brutos da resposta.
 * Não julga — só coleta.
 */
async function coletarResposta(url, opcoes = {}) {
  const metodo = opcoes.metodo || 'GET';
  const inicio = Date.now();

  const resposta = await fetch(url, {
    method: metodo,
    headers: opcoes.headers || {},
    body: opcoes.body,
    redirect: 'manual'  // não segue redirects — a gente quer VER o 301/302
  });

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
