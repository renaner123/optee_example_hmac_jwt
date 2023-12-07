# Aplicações seguras para a plataforma sama5d27-som-ek1

Este repositório contém aplicações seguras desenvolvidas com base no projeto [OP-TEE](https://optee.readthedocs.io/en/latest/general/about.html), que implementa a especificação [TEE Internal Core API](https://globalplatform.org/wp-content/uploads/2018/06/GPD_TEE_Internal_Core_API_Specification_v1.1.2.50_PublicReview.pdf). A API possibilita o acesso seguro ao TEE por parte das aplicações *hosts*.

Essas aplicações foram implementadas para serem utilizadas na plataforma [sama5d27-som-e1k](https://www.microchip.com/en-us/education/developer-help/learn-tools-software/mcu-mpu/mpu-evaluation-kits/atsama5d27-som1-ek1/features), fazendo o uso do Buildroot para construção do *kernel Linux*. O objetivo dessa implementação é viabilizar a realização de operações criptográficas em um ambiente seguro para não expor os dados sensíveis utilizados nessas operações, por exemplo, as chaves utilizadas na geração de um resumo HMAC-SHA256 ou na criação de JSON Web Tokens (JWT).


## Tabela de conteúdos
- [Aplicações seguras para a plataforma sama5d27-som-ek1](#aplicações-seguras-para-a-plataforma-sama5d27-som-ek1)
  - [Tabela de conteúdos](#tabela-de-conteúdos)
  - [Ambiente de desenvolvimento](#ambiente-de-desenvolvimento)
  - [Aplicações seguras (TA)](#aplicações-seguras-ta)
  - [Adicionando as aplicações seguras no Linux customizado](#adicionando-as-aplicações-seguras-no-linux-customizado)
    - [Utilizando as aplicações seguras deste repositório.](#utilizando-as-aplicações-seguras-deste-repositório)
  - [Passos para criar/modificar uma nova aplicação segura](#passos-para-criarmodificar-uma-nova-aplicação-segura)
  - [Referências](#referências)




## Ambiente de desenvolvimento

Para fazer modificações nos códigos desse repositório e testar na plataforma, é necessário preparar o ambiente de desenvolvimento seguindo os passos descritos na seção OP-TEE do [Linux4SAM](https://www.linux4sam.org/bin/view/Linux4SAM/ApplicationsOP-TEE#Introduction). Os passos apresentam os componentes necessários para adicionar suporte ao OP-TEE na plataforma sama5d2, tais como, *at91bootstrap*, *U-Boot*, *Kernel* e *buildroot*. Vale ressaltar que todos os passos de compilação são realizados em *cross-compile*.

## Aplicações seguras (TA)

No OP-TEE existem as aplicações de espaço do usuário (aplicações *host*) e as aplicações seguras (aplicações TA). De uma forma geral, as aplicações seguras fazem o acesso ao ambiente seguro por meio de invocações das aplicações *hosts*. Toda entrada e saída ao ambiente seguro é controlado por um monitor seguro.

Neste repositório existem duas aplicações seguras. A [primeira](/secure_storage_poc/) é uma simples adaptação da aplicação disponível em [optee-examples](https://github.com/linaro-swg/optee_examples/tree/master/secure_storage) onde é possível escrever, ler e apagar dados no armazenamento seguro do optee-os. 

A [segunda](/crypto_poc/) é uma aplicação implementada para calcular o HMAC-SHA256 e gerar tokens JWT com assinatura HMAC dentro de um ambiente seguro para não expor o segredo utilizado para gerar as assinaturas/resumos, retornando apenas a saída da função para o mundo não seguro. 

Ambas as aplicações possuem uma aplicação *host* e uma aplicação ta, assim como arquivos auxiliares. Para construção de uma aplicação segura recomenda-se seguir um padrão de estrutura de arquivos definida na documentação do OP_TEE para facilitar a orgnaização de múltiplas aplicações seguras. Segue 
a estrutura utilizada neste repositório, que respeita esse padrão.

```bash
crypto_poc/
├── Android.mk
├── CMakeLists.txt
├── host
│   ├── main.c
│   ├── main.o
│   ├── Makefile
│   └── optee_cryto_poc
├── Makefile
└── ta
    ├── ae9462ba-04f1-4ff2-aa96-d8bc7d78f509.dmp
    ├── ae9462ba-04f1-4ff2-aa96-d8bc7d78f509.elf
    ├── ae9462ba-04f1-4ff2-aa96-d8bc7d78f509.map
    ├── ae9462ba-04f1-4ff2-aa96-d8bc7d78f509.stripped.elf
    ├── ae9462ba-04f1-4ff2-aa96-d8bc7d78f509.ta
    ├── Android.mk
    ├── crypto_poc_ta.c
    ├── crypto_poc_ta.o
    ├── dyn_list
    ├── include
    │   └── crypto_poc_ta.h
    ├── Makefile
    ├── sub.mk
    ├── ta_entry_a32.o
    ├── ta.lds
    ├── user_ta_header_defines.h
    └── user_ta_header.o
```

**Obs.:** Uma TA não compartilha o espaço de armazenamento seguro com outra TA, ou seja, uma TA não consegue acessar dados gravados por outra TA

## Adicionando as aplicações seguras no Linux customizado

Para adicionar as aplicações seguras no sistema Linux construído com o Buildroot (optee-os) todos os passos da referência indicada na seção [Ambiente de desenvolvimento](#ambiente-de-desenvolvimento) devem ter ocorrido com sucesso, ou seja, é necessário que já exista uma imagem do sistema construída e todos os seus binários no diretório `buildroot-at91`.

Para compilar a aplicação *host* é necessário configurar o *cross compiler* e os arquivos gerados pelo optee-client, gerado na construção da imagem. Para isso, dentro do diretório `host` é necessário usar o seguinte comando:

```bash
make CROSS_COMPILE=<buildroot-at91>/output/host/bin/arm-buildroot-gnueabihf- TEEC_EXPORT=<buildroot-at91>/output/build/optee-client-3.15.0/out/export/usr --no-builtin-variables
```

Para compilar a aplicação ta é necessário configurar o *cross compiler* e a localização do `ta_dev_kit`, gerado na construção da imagem. Para isso, dentro do diretório `ta` é necessário usar o seguinte comando:

```bash
make CROSS_COMPILE=<buildroot-at91>/output/host/bin/arm-buildroot-gnueabihf- PLATFORM=sam TA_DEV_KIT_DIR=<buildroot-at91>/output/build/<optee-os>/out/export-ta_arm32/
```

Caso ocorra tudo certo, para adicionar a aplicação no sistema Linux é necessário copiar as aplicações compiladas para o diretório do Buildroot conforme indicado abaixo:

- Copiar o arquivo `<uuid>.ta` do diretório `ta` para \<buildroot-at91>/output/target/lib/optee_armtz/
- Copiar o binário gerado no diretório `host`` para \<buildroot-at91>/output/target/usr/bin/. Caso tenha sido alterado alguma flag de configuração na construção da imagem, a localização pode ser diferente.

Após copiar as aplicações, é necessário compilar a imagem do Buildroot novamente. Para isso, é necessário ir para o diretório `buildroot-at91` e usar `make` no terminal.


**Obs:**  Alterar \<buildroot-at91> pelo caminho no qual foi instalado

### Utilizando as aplicações seguras deste repositório.

Após gerar a nova imagem com as aplicações seguras, uma forma simples de verificar se realmente foram adicionadas é utilizando o comando `compgen -c <nome_aplicacao>`, por exemplo, `compgen -c optee` para listar todas as aplicações que começam com `optee`. Se a aplicação for listada, basta executar usando o nome da aplicação. Para a aplicação contida no diretório `crypto_poc` é possível realizar as seguintes operações:

Calcular HMAC-SHA256:
```bash
optee_crypto_poc h <key_id> <message>
```

Para gerar o HMAC, o argumento `<message>` deve estar representado em base64URL. Esse ajuste possibilita que possa ser enviado bytes como argumento (na aplicação TA é feito o *decode*).

Escrever um dado no armazenamento seguro (e.g. chave secreta):
```bash
optee_crypto_poc w <key_id> <obj_data>
```

Ler um dado armazenado no ambiente seguro (não recomendado, mas caso seja necessário)
```bash
optee_crypto_poc r <key_id> <obj_size>
```

Gerar um token JWT assinado com HMAC-SHA256
```bash
optee_crypto_poc j <key_id> <message>
```

Se a `message` for um JSON, é necessário representar como string, por exemplo, "{\"abc\":\"valor123\"}"

A aplicação `secure_storage_poc` possui a mesma dinâmica dos exemplos acima.

<!-- FIXME seguir os passos para verificar se está OK -->
## Passos para criar/modificar uma nova aplicação segura

Para criar uma aplicação, os seguintes passos podem ser usados para auxiliar e falicitar o processo:

1. Fazer uma cópia de uma aplicação segura (todo o diretório da aplicação) deste repositório ou dos exemplos disponíveis no [optee-examples](https://github.com/linaro-swg/optee_examples/tree/master). Para esse exemplo, a aplicação terá nome optee_modified.

2. Fazer as seguintes alterações na aplicação host:
    1. host/Makefile - Modificar o valor da variável `BINARY` para o nome que a aplicação terá, no caso `optee_modified`
    1. host/main.c - Alterar o nome do include que contém o UUID da aplicação para `optee_modified_ta.h`. O nome do arquivo será alterado nos passos da aplicação ta 
    1. host/main.c - Alterar o valor da variável `TEEC_UUID` para `TA_OPTEE_MODIFIED_UUID`. Essa variável será alterada nos passos da aplicação ta
    1. host/main.c - Alterar na função `TEEC_InvokeCommand(...)` o nome da macro que representa o ID do comando a ser usado para `TA_OPTEE_MODIFIED_FUNCTION`


3. Fazer as seguintes alterações na aplicação ta:
    1. ta/Android.mk - Alterar o valor do UUID da variável `local_module` para um novo valor, gerado de forma confiável. Esse UUID será usado para identificar a aplicação segura
    1. ta/user_ta_header_defines.h - Alterar o include para `optee_modified_ta.h`
    1. ta/user_ta_header_defines.h - Alterar o valor da macro `TA_UUID` para `TA_OPTEE_MODIFIED_UUID`
    1. ta/user_ta_header_defines.h - Alterar, caso exista, as ocorrências que chaman a aplicação copiada no macro `TA_CURRENT_TA_EXT_PROPERTIES` para `optee_modified`
    1. ta/sub.mk - Alterar o nome do arquvo em `srcs-y` para `optee_modified_ta.c`
    1. ta/Makefile - Adicionar o UUID adicionado em ta/Android.mk na variável `BINARY`
    1. ta/<code_example.c> - Alterar o nome do arquivo de exemplo para `optee_modified_ta.c` e também o nome do include contido no arquivo para `optee_modified_ta.h`  
    1. ta/optee_modified_ta.c – Na função TA_InvokeCommandEntryPoint(...) alterar os switch cases para refletirem ao macro `TA_OPTEE_MODIFIED_FUNCTION` ao invés dos macros do expemplo copiado
    1. ta/include/<code_example_ta.h> - Alterar o nome do arquivo para `optee_modified_ta.h` e dentro do arquivo, alterar o nome da macro UUID para `TA_OPTEE_MODIFIED_UUID` e o seu valor para o UUID gerado anteriormente.
    1. ta/include/optee_modified_ta.h - Alterar ou adicionar a macro para `TA_OPTEE_MODIFIED_FUNCTION`
    1. ta/optee_modified.c - Alterar ou adicionar a função a ser chamada pelo TA_InvokeCommandEntryPoint(...)

4. Fazer as seguintes alterações nos arquivos gerais:
   1. CMakeLists.txt -  Alterar o nome o projeto CMake para optee_modified
   1. Android.mk - Alterar o valor da variável LOCAL_MODULE para optee_modified

5. Compilar e adicionar as aplicações no sistema conforme apresentado [aqui](#adicionando-as-aplicações-seguras-no-linux-customizado).

Essas são as configurações mínimas necessárias para criar uma nova aplicação segura. A partir daqui, é necessário criar as funções e adaptar o código para refletir a necessidade da aplicação (e.g. assinaturas, HMAC, geração de chaves). 



## Referências

- [OP-TEE Linux4SAM](https://www.linux4sam.org/bin/view/Linux4SAM/ApplicationsOP-TEE#Introduction)
- [OP-TEE Documentation](https://optee.readthedocs.io/en/latest/index.html)
- [OP-TEE Examples](https://github.com/linaro-swg/optee_examples/tree/master)
- [OP-TEE OS](https://github.com/OP-TEE/optee_os/tree/master)
- [OP-TEE Tests](https://github.com/OP-TEE/optee_test)
- [TEE Internal Core API Specification](https://globalplatform.org/wp-content/uploads/2018/06/GPD_TEE_Internal_Core_API_Specification_v1.1.2.50_PublicReview.pdf) 
