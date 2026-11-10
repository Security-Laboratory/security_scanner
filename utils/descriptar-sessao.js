// Decripta manualmente o sessionHmacSecret vindo do login.
// Usa a chave privada salva em chave-privada.pem.
//
// Uso:
//   npm run descriptar -- <sessionHmacSecret-vindo-do-postman>
//
// Ex:
//   npm run descriptar -- fYe-WUtwCgRa2rINsRVDHgG4aq3_...

import { privateDecrypt, constants, createPrivateKey } from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';

const secretCifrado = process.argv[2];
if (!secretCifrado) {
	console.error('');
	console.error('❌ Faltou argumento.');
	console.error('   Uso: npm run descriptar -- <sessionHmacSecret>');
	console.error('   Cole aqui o sessionHmacSecret que veio na resposta do Postman.');
	console.error('');
	process.exit(1);
}

if (!existsSync('chave-privada.pem')) {
	console.error('');
	console.error('❌ Arquivo chave-privada.pem não existe.');
	console.error('   Rode primeiro: npm run gerar-chaves');
	console.error('');
	process.exit(1);
}

const privPem = readFileSync('chave-privada.pem', 'utf-8');
const privateKey = createPrivateKey({ key: privPem, format: 'pem' });

// Base64URL → bytes
let b64 = secretCifrado.replace(/-/g, '+').replace(/_/g, '/');
b64 += '='.repeat((4 - (b64.length % 4)) % 4);
const ciphertext = Buffer.from(b64, 'base64');

console.log('');
console.log(`── Decrypt do sessionHmacSecret ──`);
console.log(`  ciphertext len: ${ciphertext.length} bytes (RSA-2048 → esperado 256)`);
console.log('');

const combos = [
	{ oaepHash: 'sha256', mgf1Hash: 'sha256', nome: 'OAEP-SHA256/SHA256' },
	{ oaepHash: 'sha256', mgf1Hash: 'sha1',   nome: 'OAEP-SHA256/SHA1' },
	{ oaepHash: 'sha1',   mgf1Hash: 'sha1',   nome: 'OAEP-SHA1/SHA1' },
	{ oaepHash: 'sha1',   mgf1Hash: 'sha256', nome: 'OAEP-SHA1/SHA256' },
];

for (const combo of combos) {
	try {
		const plaintext = privateDecrypt(
			{
				key: privateKey,
				padding: constants.RSA_PKCS1_OAEP_PADDING,
				oaepHash: combo.oaepHash,
				mgf1Hash: combo.mgf1Hash,
			},
			ciphertext,
		);

		const texto = plaintext.toString('utf-8');
		// Aceita Base64 padrão (+/=) OU Base64URL (-_=)
		const ehBase64 = /^[A-Za-z0-9+/_-]+={0,2}$/.test(texto);

		console.log(`✓ Decrypt FUNCIONOU com ${combo.nome}`);
		console.log(`  Plaintext (len=${texto.length}): ${texto}`);
		console.log('');
		if (ehBase64) {
			// Decoda pra ver o tamanho real da chave HMAC
			const b64 = texto.replace(/-/g, '+').replace(/_/g, '/');
			const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
			const keyBytes = Buffer.from(padded, 'base64');
			console.log(`  ✓ É Base64 válido — chave HMAC de ${keyBytes.length} bytes (${keyBytes.length * 8} bits)`);
		} else {
			console.log('  ⚠️ Plaintext NÃO parece Base64 — provavelmente falso positivo');
		}
		console.log('');
		process.exit(0);
	} catch (err) {
		const msg = err.message.split(':').pop().trim();
		console.log(`✗ ${combo.nome.padEnd(22)} → ${msg}`);
	}
}

console.log('');
console.log('━━━ NENHUM padding funcionou ━━━');
console.log('');
console.log('Causas possíveis:');
console.log('  1. Server tem OUTRA pubkey cacheada pro seu IMEI/email');
console.log('     (device binding — você não é o dono do keypair atual)');
console.log('  2. Server usa parâmetros OAEP não-padrão');
console.log('  3. Server usa padding diferente (não RSA)');
console.log('');
console.log('Próximo passo: pedir pro backend resetar seu device.');
console.log('');
