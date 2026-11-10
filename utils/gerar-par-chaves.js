// Gera um par RSA 2048 e salva os dois arquivos pra uso manual:
//   chave-publica.txt → Base64 do DER SPKI (cola no Postman no campo "publicKey")
//   chave-privada.pem → formato PEM (usado depois pra decriptar)
//
// Também imprime um "fingerprint" SHA-256 — se duas execuções têm fingerprints
// diferentes, as chaves são comprovadamente diferentes.
//
// Uso: npm run gerar-chaves

import { generateKeyPairSync, createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';

const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });

const pubDer = publicKey.export({ type: 'spki', format: 'der' });
const pubB64 = pubDer.toString('base64');
const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' });

// Fingerprint único da pubkey — se duas runs têm fingerprints diferentes,
// as chaves são DIFERENTES, não importa o que o início do Base64 pareça.
const fingerprint = createHash('sha256').update(pubDer).digest('hex');

writeFileSync('chave-publica.txt', pubB64, 'utf-8');
writeFileSync('chave-privada.pem', privPem, 'utf-8');

console.log('');
console.log('✓ Par RSA 2048 gerado e salvo:');
console.log('');
console.log('  📄 chave-publica.txt  → Base64 (cola no Postman no campo "publicKey")');
console.log('  🔒 chave-privada.pem  → NÃO COMPARTILHE. Usado pra decriptar.');
console.log('');
console.log(`  🔖 Fingerprint SHA-256 da pub:`);
console.log(`     ${fingerprint}`);
console.log('');
console.log('── Chave pública (pra copiar e colar no Postman) ──');
console.log(pubB64);
console.log('');
