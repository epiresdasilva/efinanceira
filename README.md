# e-Financeira

Projeto com exemplo de assinatura e envio de XML da e-Financeira.

## Como usar

Depende da api "xmlsec", disponível para download em http://santuario.apache.org/download.html
Após realizar o download da versão Java e descompactar em seu ambiente, execute o Maven no projeto "xmlsec"

```
mvn install
```

Depois de fazer isso execute o Maven no projeto da e-Financeira.

```
mvn package
```

A classe Main é a responsável pela execução.
É necessário incluir a propriedade de VM abaixo para que gere a assinatura sem quebras.

```
-Dorg.apache.xml.security.ignoreLineBreaks=true
```

### Créditos

Confesol - Confederação das Cooperativas Centrais de Crédito Rural com Interação Solidária
