// Configuração central do scanner.
// Aqui a gente diz PRA ONDE apontar. Se amanhã você quiser testar
// o servidor da sua empresa, muda só o baseUrl. O resto do scanner
// nem precisa saber que trocou.

const ALVO = {
  baseUrl: 'http://localhost:3000',

  rotas: {
    login: '/login',       // POST { usuario, senha } → devolve JWT
    refresh: '/refresh',   // POST usando refresh cookie → devolve novo JWT
    protegida: '/perfil'   // GET com Authorization: Bearer <jwt> → dados do usuário
  },

  // Credenciais válidas pra o scanner conseguir logar e pegar um token de verdade
  // pra dissecar. Num cenário real você recebe isso do cliente que te contratou.
  credenciais: {
    usuario: 'admin',
    senha: '123456'
  }
};

export default ALVO;
