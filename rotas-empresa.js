// Catálogo COMPLETO das rotas da API da empresa.
// Fonte: configuração do gateway/proxy, mantida pelo time de infra.
//
// Organização:
//   - HOSTS     → nomes amigáveis → hostname real
//   - GRUPOS    → cada grupo tem { nome, descricao, hosts, paths, flags }
//   - Helpers   → funções pra obter grupos/paths por critério
//
// O scanner trabalha com UM host por vez (veja config.js pra escolher).
// Pra scannear outros hosts, mude o `baseUrl` no config.js e rode de novo.

// ─── Hosts ────────────────────────────────────────────────────────────
// Cada aplicação (vendas, produtor, validador) tem seu subdomínio em QAS.
// Convenção de prefixo:
//   evd* = Event Vendas 
//   evl* = Event Vendas Loja/Validador
//   epdf = Event Produtor Flutter
const HOSTS = {
	evda: 'evda.api.ev3event-qas.com.br',
	evdf: 'evdf.api.ev3event-qas.com.br',
	evla: 'evla.api.ev3event-qas.com.br',
	evlf: 'evlf.api.ev3event-qas.com.br',
	epdf: 'epdf.api.ev3event-qas.com.br',
};

// ─── Grupos de rotas ──────────────────────────────────────────────────
// Preservam exatamente a estrutura do config do gateway.
// Flags conhecidas:
//   - requireBasic: rota exige HTTP Basic auth além do Bearer token
//   - timeout: timeout específico (quando difere do padrão)
//   - clusterId: cluster alvo no proxy
const GRUPOS = [
	// ─── Ativação de PDV ─────────────────────────────────────────────
	{
		nome: 'ativacao-maquinas-vendas',
		descricao: 'Ativação de PDV por código',
		hosts: [HOSTS.evda, HOSTS.evdf],
		timeout: '00:01:00',
		paths: [
			'/api/PDVAtivacao/Ativar',
			'/api/PDVAtivacao/Preparar',
		],
	},

	// ─── Rotas Anônimas (não exigem token) ───────────────────────────
	{
		nome: 'rotas-anonimas',
		descricao: 'Rotas Anônimas (Login e Versão)',
		hosts: [HOSTS.evda, HOSTS.evdf, HOSTS.evla, HOSTS.evlf],
		paths: ['/api/Usuario/Logar'],
	},
	{
		nome: 'rotas-anonimas-produtor',
		descricao: 'Rotas Anônimas (Produtor)',
		hosts: [HOSTS.epdf],
		paths: [
			'/api/Usuario/Logar',
			'/api/AppProdutor/ChecarVersao',
		],
	},

	// ─── App Vendas ──────────────────────────────────────────────────
	{
		nome: 'setup-maquinas-vendas',
		descricao: 'Setup Máquinas Vendas',
		hosts: [HOSTS.evda, HOSTS.evdf],
		paths: ['/api/Empresa/ListarEmpresa'],
	},
	{
		nome: 'setup-maquinas-vendas-v2',
		descricao: 'Setup Máquinas Vendas v2',
		hosts: [HOSTS.evda, HOSTS.evdf],
		paths: [
			'/api/PDVConfiguration/ConsultarPDVCadastradoPorEmail',
			'/api/PDVConfiguration/ConsultarPDVCadastradoPorEmailLogado',
			'/api/PDVConfiguration/CadastrarPDV',
			'/api/PDVConfiguration/ConsultarNomePDVCadastrado',
		],
	},
	{
		nome: 'app-vendas-rota-legada',
		descricao: 'App Vendas — Rota Legada (Basic Auth)',
		hosts: [HOSTS.evda, HOSTS.evdf],
		requireBasic: true,
		paths: [
			'/api/Acao/CadastrarAcao',
			'/api/Caixa/CadastrarMovimentacaoCaixa',
			'/api/Caixa/ConsultarUsuarioCaixa',
			'/api/Carrinho/AlterarDescontoAcrescimoPedidosPorCarrinho',
			'/api/Carrinho/CadastrarCarrinho',
			'/api/Carrinho/CancelarProdutosCartaoNfc',
			'/api/Carrinho/GerarLinkPagamento',
			'/api/Carrinho/ListaCarrinhoPorPDV',
			'/api/Carrinho/ListaMapaMesa',
			'/api/Carrinho/NovoCarrinho',
			'/api/Carrinho/RetornaCarrinhoPorCodIdentificacao',
			'/api/Carrinho/RetornaComanda',
			'/api/Carrinho/RetornaComandasAbertas',
			'/api/Carrinho/RetornaExtratoCartaoNfc',
			'/api/Carrinho/RetornaExtratoPorCarrinho',
			'/api/Carrinho/RetornaListaItensPorCarrinho',
			'/api/Carrinho/RetornaListaItensPorComanda',
			'/api/Carrinho/RetornaListaItensPorPedidoCarrinho',
			'/api/Carrinho/RetornaListaPagamentosPorCarrinho',
			'/api/Carrinho/RetornaListaPedidosPorCarrinho',
			'/api/Carrinho/RetornaProdutosCartaoNfc',
			'/api/Carrinho/TransfereProdutoCarrinho',
			'/api/CartaoNfc/CadastrarCartaoNfc',
			'/api/CartaoNfc/ConsultaCartaoNfcPorCpf',
			'/api/CartaoNfc/ConsultarControleCartaoNfc',
			'/api/Cliente/RetornaClientePorCel',
			'/api/Cliente/RetornaClientePorCpf',
			'/api/DescontoAcrecimo/ConsultarDescontoAcrecimo',
			'/api/EstoqueProduto/ConsultarEstoqueProduto',
			'/api/EstoqueProduto/ReservaProduto',
			'/api/EstoqueProduto/ConfirmaPedidoReservaProduto',
			'/api/Kit/ConsultarComposicaoKit',
			'/api/LancamentoVenda/CadastrarLancamentoVenda',
			'/api/LancamentoVenda/CadastrarLancamentoVendaDetalhe',
			'/api/Logger/Log',
			'/api/MeioPagamento/ConsultarMeioPagamento',
			'/api/Modificadores/ConsultarModificadores',
			'/api/NotaFiscal/CancelaNotaFiscal',
			'/api/NotaFiscal/EmitirNotaFiscal',
			'/api/NotaFiscal/GerarQrCodeNotaFiscal',
			'/api/PDVConfiguration/AtualizarPDVCadastrado',
			'/api/PDVConfiguration/AtualizarSerialNumberPDVCadastrado',
			'/api/PDVConfiguration/AtualizarTokenFireBase',
			'/api/Pedido/CadastrarPedido',
			'/api/Pedido/CadastrarPedidoDetalhe',
			'/api/Pedido/CancelarPedidoDetalheMesa',
			'/api/Pedido/CancelarTicketPorCod',
			'/api/Pedido/EnviarEmailPedido',
			'/api/Pedido/ListarLancamentoVendaDetalheCanceladosSync',
			'/api/Pedido/RetornaQrCodeVoucherPorCod',
			'/api/Pedido/TrocarTicket',
			'/api/PontoDeProducao/ImprimirCarrinho',
			'/api/Sangria/CadastrarSangria',
			'/api/Sangria/ListarSangriasSync',
			'/api/Sync/Confirmar',
			'/api/Usuario/CadastrarCartaoNfcAdmin',
			'/api/Usuario/CadastrarOperadorSync',
			'/api/Usuario/ConsultarOperador',
			'/api/Usuario/ConsultarUsuarioPerfil',
			'/api/Validacao/CadastrarValidacao',
			'/api/Validacao/CadastrarValidacaoProduto',
			'/api/Validacao/CadastrarValidacaoVoucher',
			'/api/Validacao/ConsultarValidacaoProduto',
			'/api/Validacao/ConsultarValidacaoVoucher',
			'/api/Validacao/ValidarVoucher',
			'/api/Voucher/CadastrarVoucherTroco',
			'/api/Cliente/ConsultarCliente',
			'/api/Usuario/ConsultarPermissoesPdv',
		],
	},
	{
		nome: 'app-vendas-v2',
		descricao: 'App Vendas v2',
		hosts: [HOSTS.evda, HOSTS.evdf, HOSTS.epdf],
		paths: [
			'/api/PontoVenda/ConsultarPontoVenda',
			'/api/PontoVenda/ConsultarEstruturaVenda',
			'/api/PDVConfiguration/CadastrarPDVPontoVenda',
			'/api/PDVConfiguration/ConsultarPDVCadastrado',
			'/api/PDVConfiguration/DesativarPDVCadastrado',
			'/api/PDVConfiguration/AtualizarStatusBateria',
			'/api/PDVConfiguration/AtualizarLocalizacao',
			'/api/PDVConfiguration/AtualizarTelemetria',
			'/api/PDVConfiguration/RegistrarChamadaSuporte',
			'/api/PDVConfiguration/ConsultarComandosPendentes',
			'/api/PDVConfiguration/AtualizarStatusComando',
			'/api/Cliente/CadastrarCliente',
			'/api/Cliente/ValidarIdentidadeCliente',
		],
	},

	// ─── App Administrador ───────────────────────────────────────────
	{
		nome: 'app-administrador-v2',
		descricao: 'App Administrador',
		hosts: [HOSTS.epdf],
		paths: [
			'/api/Administrador/ConsultarCentralAlertas',
			'/api/Administrador/ObterCanalNotificacoes',
			'/api/Administrador/RegistrarPushToken',
			'/api/Administrador/AtenderChamada',
			'/api/Administrador/FinalizarChamada',
		],
	},

	// ─── App Produtor ────────────────────────────────────────────────
	{
		nome: 'setup-app-produtor',
		descricao: 'Setup Máquinas App Produtor',
		hosts: [HOSTS.epdf],
		paths: ['/api/Empresa/ListarEmpresa'],
	},
	{
		nome: 'setup-app-produtor-v2',
		descricao: 'Setup Máquinas App Produtor v2',
		hosts: [HOSTS.epdf, HOSTS.evdf],
		paths: ['/api/AppProdutor/SelecionarEmpresa'],
	},
	{
		nome: 'app-produtor-legacy',
		descricao: 'App Produtor Flutter',
		hosts: [HOSTS.epdf],
		paths: [
			'/api/AppProdutor/DetalhePontosDeVendaMeioPagamento',
			'/api/AppProdutor/ListaEventoDiaPorEvento',
			'/api/AppProdutor/ListaEventosAtivos',
			'/api/AppProdutor/ListaEventosPorData',
			'/api/AppProdutor/ListaItensVendidos',
			'/api/AppProdutor/ListarCanceladosResumidaPorEvento',
			'/api/AppProdutor/ListarValidacaoResumidaPorEvento',
			'/api/AppProdutor/MovimentacaoCaixaResumido',
			'/api/AppProdutor/PontosDeVenda',
			'/api/AppProdutor/RetornaUsuario',
			'/api/AppProdutor/TotaisResumoVendaEvento',
			'/api/AppProdutor/TotalizadorVendaProdutosPorGrupo',
			'/api/AppProdutor/TotalizadorVendaValoresPorGrupo',
			'/api/AppProdutor/TotalValidadoPorEvento',
		],
	},

	// ─── App Validador ───────────────────────────────────────────────
	{
		nome: 'setup-maquinas-validador',
		descricao: 'Setup Máquinas Validador',
		hosts: [HOSTS.evla, HOSTS.evlf],
		paths: ['/api/Empresa/ListarEmpresa'],
	},
	{
		nome: 'setup-maquinas-validador-v2',
		descricao: 'Setup Máquinas Validador v2',
		hosts: [HOSTS.evla, HOSTS.evlf],
		clusterId: 'v2-api-cluster',
		paths: [
			'/api/ValidadorConfiguration/ConsultarPDVCadastradoPorEmail',
			'/api/ValidadorConfiguration/ConsultarPDVCadastradoPorEmailLogado',
			'/api/ValidadorConfiguration/CadastrarPDV',
			'/api/ValidadorConfiguration/ConsultarNomePDVCadastrado',
		],
	},
	{
		nome: 'app-validador',
		descricao: 'App Validador',
		hosts: [HOSTS.evla, HOSTS.evlf],
		paths: [
			'/api/Caixa/CadastrarMovimentacaoCaixa',
			'/api/Caixa/ConsultarUsuarioCaixa',
			'/api/Kit/ConsultarComposicaoKit',
			'/api/Logger/Log',
			'/api/PontoRetirada/ConsultarPontoRetirada',
			'/api/PontoValidacao/ConsultarEstruturaVendaValidacao',
			'/api/Sync/Confirmar',
			'/api/Validacao/CadastrarValidacao',
			'/api/ValidadorUsuarios/CadastrarOperadorSync',
			'/api/ValidadorUsuarios/ConsultarOperador',
			'/api/ValidadorValidacao/CadastrarValidacaoProduto',
			'/api/ValidadorValidacao/ConsultarValidacaoProduto',
			'/api/ValidadorValidacao/RetornaQrCodeTicketPorCod',
			'/api/ValidadorValidacao/ValidarProduto',
			'/api/ValidadorValidacao/ValidarProdutoExterno',
			'/api/ValidadorValidacao/ValidarProdutoUnico',
			'/api/ValidadorValidacao/VerificarValidacaoProduto',
			'/api/EquipeEvento/Movimento/Registrar',
		],
	},
	{
		nome: 'app-validador-v2',
		descricao: 'App Validador v2',
		hosts: [HOSTS.evla, HOSTS.evlf],
		paths: [
			'/api/ValidadorConfiguration/ConsultarPDVCadastrado',
			'/api/ValidadorConfiguration/DesativarPDVCadastrado',
			'/api/ValidadorConfiguration/CadastrarPDVPontoRetirada',
		],
	},
];

// ─── Helpers ──────────────────────────────────────────────────────────

/** Devolve o grupo pelo nome, ou null se não achar. */
function obterGrupo(nome) {
	return GRUPOS.find((g) => g.nome === nome) || null;
}

/** Lista todos os grupos servidos num host específico. */
function gruposPorHost(host) {
	return GRUPOS.filter((g) => g.hosts.includes(host));
}

/** Todos os paths "anônimos" (sem Bearer) nesse host. */
function pathsAnonimosPorHost(host) {
	return gruposPorHost(host)
		.filter((g) => g.nome.startsWith('rotas-anonimas'))
		.flatMap((g) => g.paths);
}

/** Todos os paths "protegidos" (exigem Bearer) nesse host. */
function pathsProtegidosPorHost(host) {
	return gruposPorHost(host)
		.filter((g) => !g.nome.startsWith('rotas-anonimas'))
		.flatMap((g) => g.paths);
}

/** Lista flat de todos os paths num host (anônimos + protegidos), sem duplicatas. */
function todosPathsPorHost(host) {
	const set = new Set();
	for (const g of gruposPorHost(host)) for (const p of g.paths) set.add(p);
	return [...set];
}

export {
	HOSTS,
	GRUPOS,
	obterGrupo,
	gruposPorHost,
	pathsAnonimosPorHost,
	pathsProtegidosPorHost,
	todosPathsPorHost,
};
