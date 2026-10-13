# brazilpe — MCPE 0.15.10 para iOS ARM64

Implementação nativa integrada ao executável do IPA fornecido. **O IPA produzido é sem assinatura e ainda não foi testado num iPhone físico.** O código e o comportamento dos módulos ARM64 foram verificados por análise estática e emulação; isso não comprova compatibilidade com o iOS informado nem aceitação de golpes por servidores.

Não existe menu, botão ou overlay novo. O módulo amplia a caixa **temporária de seleção** dos jogadores, sem redimensionar o corpo, a colisão física ou a função que calcula a sombra. Somente quatro tabelas virtuais identificadas como jogadores recebem o novo retorno de margem. As outras entidades mantêm sua margem original. Os limites de distância da seleção são alterados separadamente e também podem afetar a seleção de outras entidades.

## Usar o arquivo entregue

O arquivo `MCPE-0.15.10-hitbox-unsigned.ipa` precisa ser **assinado novamente** e instalado usando uma ferramenta de sideload compatível com seu iOS e sua conta/certificado. Não exige jailbreak para o módulo rodar: a modificação já está dentro do executável, sem injeção em outro processo nem alteração de memória executável durante o jogo. O ambiente desta produção não tem certificado Apple nem dispositivo iOS; a assinatura e a instalação não foram realizadas.

Depois da primeira execução, procure em **Arquivos → No Meu iPhone → Minecraft PE → mcpe-hitbox → hitbox.cfg**. O contêiner exato exibido pelo instalador pode ter outro nome. O caminho relativo é `Documents/mcpe-hitbox/hitbox.cfg`; o IPA original já habilita compartilhamento de arquivos. A ferramenta de instalação também pode permitir acessar os documentos do aplicativo pelo computador.

```ini
enabled=1
radius=0.75
reach=6
```

- `enabled=0` restaura os valores originais da margem e dos limites alterados. `1` ativa a configuração.
- `radius` aceita **0.1 a 8**, em blocos, adicionados em cada direção à caixa de seleção. É uma margem, não um multiplicador. O valor original desse método é `0.1`; `0.75` amplia a largura em `1.5` bloco no total. Não altera o tamanho visual.
- `reach` aceita **3 a 12** blocos para os limites de seleção modificados. O módulo não reduz a distância que o modo de jogo já fornece. A distância de um golpe aceito continua sujeita às regras do servidor.

Salve exatamente essas três linhas em texto ASCII/UTF-8 sem BOM, com ponto decimal e sem comentários. A leitura é atualizada no máximo uma vez por segundo durante a seleção de alvos. Configuração incompleta, desativada, fora dos limites, com NaN/infinito, texto extra ou mais de 126 bytes restaura os valores originais. Não exige reconstruir o IPA para editar o arquivo de documentos.

O primeiro lançamento cria a configuração acima se ela ainda não existir. A criação é exclusiva e não sobrescreve um arquivo existente quando a abertura para leitura falha. Não há mecanismos de ocultação contra verificadores nem garantia de indetectabilidade.

## Reproduzir o build

Execute os comandos abaixo dentro da pasta do repositório `brazilpe`.

Python 3.10+; funciona sem SDK Apple e sem compilador C++, pois monta os módulos ARM64 diretamente. O IPA e certificados ficam fora do Git.

```bash
python3 -m pip install -r requirements.txt
python3 build.py /caminho/LunarLarixBlizzard.ipa \
  --output outputs/MCPE-0.15.10-hitbox-unsigned.ipa
```

Edite `hitbox.cfg` antes do build para escolher os valores iniciais, ou passe `--config /caminho/hitbox.cfg`. O arquivo também é incluído em `Payload/minecraftpe.app/data/mcpe-hitbox/hitbox.cfg` como referência dos valores usados; **o arquivo ativo editável é o de Documents**, criado pelo código nativo. Alterar arquivos dentro do aplicativo depois da assinatura invalida essa assinatura.

O construtor não toca no IPA original. Exige o SHA-256 exato do executável inspecionado, verifica instruções e slots virtuais, preserva os endereços originais de código/dados, mantém os registros de rebase ASLR e os imports, e remove a assinatura inválida do executável modificado. Outro IPA 0.15.10 com executável diferente é bloqueado; não adivinha offsets.

## Testes

```bash
python3 -m pip install -r requirements-test.txt
MCPE_TEST_IPA=/caminho/LunarLarixBlizzard.ipa \
  python3 -m unittest discover -s tests -v
```

Sem `MCPE_TEST_IPA`, os testes dependentes do binário são marcados como não executados. A emulação executa as instruções geradas com ASLR, confere a ABI variádica Apple ARM64, preservação de registradores/pilha, reload, limites e concorrência. As chamadas de arquivos são simuladas e a conversão scanf é executada pela libc da máquina de testes. Não é uma simulação completa do iOS nem uma partida real.

## Arquivos e mecanismo

- `profile.json`: identidade do executável, posições verificadas e guardas da versão.
- `src/runtime.S.in`: leitura bounded da configuração pelos imports C já presentes no jogo, com lock não bloqueante e cache de um segundo.
- `src/macho.py`: leitor Mach-O, stubs, rebase e inserção de segmentos RX e RW separados.
- `build.py`: monta as rotinas, substitui os quatro ponteiros e os cinco pontos guardados de seleção, e empacota o IPA sem assinatura.
- `tests/test_runtime.py`: testes das instruções ARM64 e integridade do Mach-O.
- `VALIDATION.json`: resultado real das verificações desta entrega.

O executável original usa a chamada virtual de margem no slot `0x248` e expande uma cópia da AABB antes da interseção do raio. Os quatro jogadores selecionados compartilham o método de tipo que retorna `0x13f` no slot `0x2b0`. A função original de sombra, os slots correspondentes, dimensões físicas e assets gráficos permanecem intactos. A busca ampla de candidatos acompanha a margem configurada, e os dois limites locais de três blocos usam a distância configurada, mantendo bloqueio por obstáculos e o restante do fluxo original.

Primeiro diagnóstico se não instalar: conferir a assinatura e o perfil de provisionamento com a ferramenta usada. Se instalar mas não abrir, é necessário coletar o relatório de crash do dispositivo: o lançamento no iOS físico permanece pendente. Se selecionar mas não causar dano à distância, conferir a validação do servidor; o módulo não muda seu código.
