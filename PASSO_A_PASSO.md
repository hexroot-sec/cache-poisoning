# Cache Poisoning Hunter — passo a passo (DETECTAR → PORTÃO → CHECAR → VALIDAR)

Baseado em: PortSwigger Web Cache Poisoning, Intigriti "Exploiting Web Cache Poisoning
Vulnerabilities", YesWeHack Cache Key Injection ([[ref-xss-cachepoison]]).

**v0.2 — modo SNIPER (toggle no popup):** roda a suíte inteira SOZINHO ao navegar
(só quando cache é detectado no passivo e o portão prova o buster). Extras de sniper:
- **Classificação de impacto**: reflexão cacheada em `src=` de `<script>` vira
  `XSS-src-envenenado` (não é só "refletido").
- **PoC de 1 clique**: toast traz link "🔗 abrir envenenado" — abre a URL com o MESMO
  buster SEM o header → a página vem envenenada (prova visual; chave é só sua).
- **ESI injection (RCE path)**: injeta `<esi:include src="...">` via header que já
  refletiu no corpo; se a tag voltar PROCESSADA/removida (não crua) = edge com ESI
  ativo → SSRF/RCE no CDN. Só roda em headers com reflexão no CORPO (redirect engole
  a tag e daria falso positivo).
- **Param cloaking**: `?zzcpQ=canary&zzcpQ=chave` — se o backend usa o 1º valor e o
  cache chaveia o último, pedir só a chave devolve o conteúdo do canary = cache key
  mismatch (envenenamento sutil de chave).
- **📋 Copiar report** no popup: snippet pronto com achados + URLs PoC.

## 0. Regra de ouro (a extensão IMPLEMENTA, não só documenta)

1. **Cache-buster ÚNICO em toda request** (param `zzcp*` com valor aleatório) → a resposta
   envenenada só cai na SUA chave. Nunca envenena chave compartilhada.
2. **Portão antes de tudo**: provar que o buster É keyed (repeat → HIT; chave nova → MISS).
   Se não provar, NENHUM teste é enviado (query unkeyed + buster = envenenaria usuário real).
3. Confirmar que cada probe só afeta a própria request. Preferir dev/não-prod. Em VDP
   financeiro, envenenar usuário real = linha vermelha.

## 1. DETECTAR (passivo — a extensão faz)

- Headers de cache: `X-Cache`, `X-Cache-Status`, `CF-Cache-Status`, `Age`, `Cache-Control`,
  `Via`, `X-Served-By`, `Server`, `X-Cache-Hits`.
- `Vary` presente = os headers listados SÃO keyed (não são testáveis por cache poisoning).
- Sem headers → pode não haver cache nesta URL (o portão confirma).

## 2. PORTÃO (a extensão faz — passo 0 automático)

buster A: request 2× → 2ª tem que vir HIT. buster B (chave nova): tem que vir MISS.
`keyed = hit2 && miss3`. Só com keyed=true os testes rodam.

## 3. CHECAR (a extensão faz, 1 request envenenada por header, na própria chave)

Headers candidatos (unkeyed clássicos): `X-Forwarded-Host`, `X-Forwarded-Scheme`,
`X-Forwarded-Port`, `X-Forwarded-Proto`, `X-Forwarded-For`, `X-Host`, `X-Original-URL`,
`X-Rewrite-URL`, `X-HTTP-Method-Override` (CPDoS), `Forwarded`, `X-Real-IP`,
`Accept-Language` + variantes de bypass: `X_Forwarded_Host`, `X.Forwarded.Host`.

Para cada header: request com `Header: canary` + buster → procura canary em
`src=`/`href=`/`content=` (meta/OG)/`action=`/corpo. Depois request com o MESMO buster
SEM o header → se a resposta ainda contém o canary (+ HIT/Age) = **envenenada em cache**.

Testes extras: redirect (301/302 com canary no destino, reuso cacheado) e CPDoS
(`X-HTTP-Method-Override` → erro 4xx/5xx cacheado para a chave).

## 4. VALIDAR para o report (manual, depois do CONFIRMADO da extensão)

1. Repetir em outro dispositivo/rede (provar que a chave é compartilhada, não da sessão).
2. Anotar TTL (`Cache-Control: max-age`) — TTL curto enfraquece o impacto.
3. Evidências: request exata (header + buster), HIT no repeat, resposta limpa servindo o
   conteúdo envenenado, screenshot.
4. Impacto real: XSS via `<script src>` envenenado, redirect para phishing, CPDoS (DoS).

## Limitações da extensão

- `Host` não dá pra alterar via fetch do navegador — testar manualmente (Burp/Caido).
- Cache key injection (YesWeHack) e param cloaking são variantes manuais — ver doc na memória.
- Se a query NÃO for keyed, a extensão bloqueia (correto): teste manual só com buster
  provado em outro componente keyed (path, Host).
- `fetch` usa `cache:'no-store'` sempre — o cache do NAVEGADOR nunca mascara o do servidor.

## Uso

- Abrir a página do alvo → passivo roda sozinho (badge: CACHE quando detecta cache).
- Popup → "▶ Rodar testes" (portão automático antes; BLOQUEADO se não provar o buster).
- Teste automatizado (lab/CDP): `?__cp_autotest=1` na URL.
- Lab local: `lab/server.py` (porta 8767) — emula CDN (chave = zzcp* name=value;
  headers unkeyed): `/` reflete X-Forwarded-Host em `<script src>` e canonical,
  X-Original-URL → 301, X-HTTP-Method-Override → 405; `/nocache` = controle negativo.
- Depurar: div `#__cpsniper_debug` (JSON: passivo/portão/testes).
