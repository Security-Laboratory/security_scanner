# Security Scanner

Scanner de segurança para APIs REST — audita autenticação, cookies e HTTPS, e simula os ataques mais comuns contra JWT.

## O que ele faz

Aponta pra uma URL, roda uma bateria de testes e devolve uma nota de 0 a 100 com o detalhamento das falhas encontradas.

Testes previstos (implementação por fase, ver Roadmap):

- **Rede**: força HTTPS? Redireciona HTTP → HTTPS? Cifras TLS aceitas?
- **Cookies**: `HttpOnly`, `Secure`, `SameSite` estão presentes no `Set-Cookie` do login?
- **JWT**: qual algoritmo? Qual tempo de vida do access token? As claims (`exp`, `iat`, `iss`, `aud`) estão corretas?
- **Ataques ativos**:
  - Ataque `alg: none` — servidor aceita JWT sem assinatura?
  - Brute-force HMAC — chave secreta é adivinhável a partir de uma wordlist?

Cada falha é classificada por gravidade (`baixa`, `media`, `alta`, `critica`) e desconta pontos da nota inicial.

## Estrutura

```
security_scanner/
├── index.js            Orquestrador — carrega config, roda os scanners, imprime resumo
├── config.js           Alvo do scan (baseUrl, rotas, credenciais)
├── eslint.config.js    Regras de análise estática
├── scanners/           Um arquivo por família de teste (rede, cookies, jwt, ataques)
└── utils/
    ├── http.js         Dispatcher HTTP compartilhado por todos os scanners
    └── motor.js        Motor de pontuação e log colorido no terminal
```

## Como rodar

Requisitos: Node.js 18+.

```bash
npm start          # roda o scanner uma vez
npm run dev        # roda com --watch (reinicia ao editar)
npm run lint       # verifica o código com ESLint
```

Sem parâmetros: usa o alvo definido em `config.js` (por padrão, o `alvo_cobaia` local em `http://localhost:3000`).

## Inspeção manual

Pra ver a resposta HTTP crua de uma rota (headers, cookies, body) sem passar pelo scanner, use `curl.exe -i` direto no terminal do Windows (CMD):

```bash
curl.exe -i -X POST http://localhost:3000/login -H "Content-Type: application/json" -d "{\"usuario\":\"admin\",\"senha\":\"123456\"}"
```

O flag `-i` inclui os headers da resposta. Você vê `Set-Cookie`, `X-Powered-By`, status code, tudo. Útil pra debug ou pra confirmar na mão o que o scanner detectou.

No PowerShell, use `curl.exe` explícito (o `curl` sozinho é apelido pro `Invoke-WebRequest`, sintaxe diferente).

## Configurar um alvo diferente

Edite `config.js`:

```js
const ALVO = {
  baseUrl: 'https://api.suaempresa.com',
  rotas: {
    login: '/auth/login',
    refresh: '/auth/refresh',
    protegida: '/me'
  },
  credenciais: { usuario: '...', senha: '...' }
};
```

## Roadmap

- [x] **Fase 1** — Esqueleto, config, motor de pontuação
- [x] **Fase 2** — Auditoria de rede e cookies (HTTPS, `Set-Cookie`)
- [ ] **Fase 3** — Decodificação e validação de JWT (`.split('.')`, Base64URL, claims)
- [ ] **Fase 4** — Simulador de exploits (`alg:none`, brute-force HMAC)
- [ ] **Fase 5** — Consolidação de score e geração de relatório (Markdown / JSON)

## Aviso legal

Ferramenta educacional. Só use contra servidores que **você mesmo administra** ou tem **autorização formal por escrito** para testar. Rodar contra sistemas de terceiros sem autorização caracteriza crime (Lei 12.737/2012 no Brasil).
