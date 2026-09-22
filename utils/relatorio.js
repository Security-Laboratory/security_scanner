// Gerador de relatório final.
// Recebe o resumo do motor + o alvo, cospe dois arquivos em relatorios/:
//   - relatorio-<timestamp>.md   (legível pra humano)
//   - relatorio-<timestamp>.json (consumível por CI, dashboards, etc.)

import { writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { obterRemediacao } from './remediacoes.js';

const ORDEM_GRAVIDADE = { critica: 0, alta: 1, media: 2, baixa: 3 };

const ICONE_GRAVIDADE = {
	critica: '🔴',
	alta: '🟠',
	media: '🟡',
	baixa: '🔵',
};

/**
 * Timestamp humano: 2026-09-21 19:35:12
 */
function timestampHumano() {
	const d = new Date();
	const pad = (n) => String(n).padStart(2, '0');
	return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

/**
 * Agrupa achados por categoria com contagens e nota parcial.
 */
function agruparPorCategoria(achados) {
	const grupos = {};
	const PENALIDADES = { baixa: 2, media: 5, alta: 10, critica: 20 };

	for (const a of achados) {
		if (!grupos[a.categoria]) {
			grupos[a.categoria] = { total: 0, passaram: 0, falharam: 0, nota: 100 };
		}
		const g = grupos[a.categoria];
		g.total++;
		if (a.passou) g.passaram++;
		else {
			g.falharam++;
			g.nota -= PENALIDADES[a.gravidade] || 0;
		}
	}

	for (const cat in grupos) {
		grupos[cat].nota = Math.max(0, grupos[cat].nota);
	}
	return grupos;
}

/**
 * Ícone da nota geral baseado na nota final.
 */
function iconeNota(nota) {
	if (nota >= 80) return '🟢';
	if (nota >= 50) return '🟡';
	return '🔴';
}

function gerarMarkdown(resumo, alvo) {
	const { total, passaram, falharam, nota, achados } = resumo;

	// Separa passou/falhou e ordena por gravidade (crítica primeiro)
	const falhas = achados
		.filter((a) => !a.passou)
		.sort((a, b) => ORDEM_GRAVIDADE[a.gravidade] - ORDEM_GRAVIDADE[b.gravidade]);
	const sucessos = achados.filter((a) => a.passou);

	const grupos = agruparPorCategoria(achados);

	let md = '';
	md += `# Relatório de Segurança\n\n`;
	md += `**Alvo:** ${alvo.baseUrl}\n`;
	md += `**Data:** ${timestampHumano()}\n\n`;
	md += `## Nota Final: ${nota}/100 ${iconeNota(nota)}\n\n`;

	md += `| Métrica | Valor |\n|---|---|\n`;
	md += `| Testes rodados | ${total} |\n`;
	md += `| Passaram | ${passaram} |\n`;
	md += `| Falharam | ${falharam} |\n\n`;

	// ─── Breakdown por categoria ─────────────────────────────
	md += `## Por categoria\n\n`;
	md += `| Categoria | Passou | Falhou | Nota |\n|---|---|---|---|\n`;
	for (const cat of Object.keys(grupos).sort()) {
		const g = grupos[cat];
		md += `| ${cat} | ${g.passaram} | ${g.falharam} | ${g.nota}/100 |\n`;
	}
	md += `\n`;

	// ─── Falhas detalhadas ───────────────────────────────────
	if (falhas.length > 0) {
		md += `## Falhas encontradas (${falhas.length})\n\n`;
		md += `Ordenadas por gravidade.\n\n`;
		for (const f of falhas) {
			const icone = ICONE_GRAVIDADE[f.gravidade] || '';
			md += `### ${icone} ${f.gravidade.toUpperCase()} — ${f.descricao}\n\n`;
			md += `- **Categoria:** ${f.categoria}\n`;
			md += `- **ID:** \`${f.id}\`\n\n`;
			if (f.detalhes) md += `**Detalhes:** ${f.detalhes}\n\n`;
			const correcao = obterRemediacao(f.id);
			if (correcao) md += `**Como corrigir:** ${correcao}\n\n`;
			md += `---\n\n`;
		}
	} else {
		md += `## Falhas encontradas: nenhuma 🎉\n\n`;
	}

	// ─── Testes que passaram ─────────────────────────────────
	if (sucessos.length > 0) {
		md += `## Testes aprovados (${sucessos.length})\n\n`;
		for (const s of sucessos) {
			md += `- ✓ [${s.categoria}] ${s.descricao}\n`;
		}
		md += `\n`;
	}

	md += `---\n\n`;
	md += `_Gerado por security_scanner — não substitui pentest profissional._\n`;
	return md;
}

function gerarJSON(resumo, alvo) {
	const grupos = agruparPorCategoria(resumo.achados);
	return {
		alvo: alvo.baseUrl,
		geradoEm: new Date().toISOString(),
		notaFinal: resumo.nota,
		total: resumo.total,
		passaram: resumo.passaram,
		falharam: resumo.falharam,
		porCategoria: grupos,
		achados: resumo.achados.map((a) => ({
			...a,
			correcao: !a.passou ? obterRemediacao(a.id) : undefined,
		})),
	};
}

/**
 * Gera os dois arquivos em relatorios/ e retorna os caminhos.
 * Sempre sobrescreve — pra manter a pasta limpa e sempre ter o último scan
 * como referência única. Se você quiser histórico, comita os arquivos ou
 * troque o nome pra timestampArquivo() e ajuste o .gitignore.
 */
function gerarRelatorio(resumo, alvo) {
	const pastaRelatorios = 'relatorios';
	if (!existsSync(pastaRelatorios)) mkdirSync(pastaRelatorios);

	const caminhoMd = `${pastaRelatorios}/relatorio.md`;
	const caminhoJson = `${pastaRelatorios}/relatorio.json`;

	writeFileSync(caminhoMd, gerarMarkdown(resumo, alvo), 'utf-8');
	writeFileSync(caminhoJson, JSON.stringify(gerarJSON(resumo, alvo), null, 2), 'utf-8');

	return { md: caminhoMd, json: caminhoJson };
}

export { gerarRelatorio };
