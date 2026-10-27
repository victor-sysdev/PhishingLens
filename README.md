# 🛡️ PhishingLens

**Inteligência artificial aplicada à detecção de phishing e engenharia social.**

O PhishingLens é uma ferramenta de análise de mensagens suspeitas desenvolvida em Python. O projeto combina análise estática baseada em regras com inteligência artificial generativa usando **Gemma 4 por meio da API Gemini**, com o objetivo de identificar possíveis tentativas de phishing e explicar os riscos encontrados.

A proposta é transformar indicadores técnicos em informações claras e recomendações práticas para o usuário.

> **Status:** Em desenvolvimento — protótipo funcional do analisador local, com interface e integração com Gemma 4 em construção.

---

## 🎯 Objetivo

Desenvolver uma ferramenta acessível que ajude a identificar sinais de phishing em e-mails e mensagens, combinando análise programática e interpretação contextual por inteligência artificial.

O projeto busca explorar a aplicação de modelos de linguagem na segurança da informação, especialmente na identificação de técnicas de engenharia social.

## ✨ Funcionalidades

### Implementadas

- [x] Análise de mensagens por regras locais.
- [x] Identificação de indicadores suspeitos.
- [x] Extração de URLs sem acessar os endereços.
- [x] Classificação inicial de risco.
- [x] Recomendações baseadas na análise.
- [x] Testes automatizados com pytest.

### Em desenvolvimento

- [X] Integração do Gemma 4 via API Gemini.
- [X] Análise contextual de mensagens com IA.
- [X] Identificação de técnicas de engenharia social por IA.
- [X] Exibição conjunta dos resultados da análise local e da IA.
- [X] Tratamento de erros, respostas inválidas e falhas na API.
- [X] Refinamento da interface e da experiência do usuário.

## 🧠 Como funciona

O PhishingLens está sendo desenvolvido com uma arquitetura que combina duas abordagens complementares.

### 1. Análise estática

O analisador local examina o texto usando regras programáticas para identificar sinais como:

- Linguagem de urgência ou pressão.
- Solicitações de senhas e dados sensíveis.
- Frases potencialmente suspeitas.
- Características suspeitas em URLs.

As URLs são extraídas para análise textual, sem que a aplicação precise visitar os sites.

### 2. Análise com inteligência artificial

A integração planejada utiliza o **Gemma 4**, disponibilizado pela API Gemini, para interpretar o contexto da mensagem.

A camada de IA deverá auxiliar na identificação de:

- Possíveis tentativas de engenharia social.
- Solicitações suspeitas de informações confidenciais.
- Mensagens que simulam comunicações legítimas.
- Indícios contextuais que regras simples podem não detectar.

O modelo deverá apresentar uma explicação dos indicadores encontrados, além de recomendações para o usuário.

### 3. Apresentação dos resultados

A interface deverá reunir as informações em uma visualização objetiva, contendo:

- Classificação de risco.
- Indicadores identificados.
- URLs extraídas.
- Explicação contextual da IA.
- Recomendações de segurança.

**Importante:** a ausência de indicadores não significa que uma mensagem seja segura. A análise por regras e a IA podem cometer erros, portanto os resultados devem ser tratados como apoio à decisão, não como garantia de segurança.

## 🏗️ Tecnologias

| Tecnologia | Aplicação |
|---|---|
| Python | Lógica principal e análise de mensagens |
| Streamlit | Interface web |
| Gemma 4 | Análise contextual com IA |
| API Gemini | Acesso ao modelo Gemma 4 |
| Google Gen AI SDK | Comunicação com a API |
| pytest | Testes automatizados |
| python-dotenv | Gerenciamento de variáveis de ambiente |

## 📂 Estrutura do projeto

```text
PhishingLens/
├── tests/
│   └── test_analyzer.py
├── .env.example
├── .gitignore
├── ai_analyzer.py
├── analyzer.py
├── app.py
├── README.md
├── requirements.txt
└── LICENSE
```

- `app.py`: interface da aplicação.
- `analyzer.py`: regras locais e extração de URLs.
- `ai_analyzer.py`: integração com o modelo de inteligência artificial.
- `tests/test_analyzer.py`: testes automatizados.
- `.env.example`: exemplo das variáveis de ambiente necessárias.
- `requirements.txt`: dependências do projeto.

## ⚙️ Instalação

### Pré-requisitos

- Python 3.11 ou superior, com compatibilidade das dependências instaladas.
- Git.
- Uma chave de API Gemini para testar a integração com o modelo.

### 1. Clone o repositório

```bash
git clone <URL_DO_REPOSITORIO>
cd PhishingLens
```

Substitua `<URL_DO_REPOSITORIO>` pelo endereço do repositório.

### 2. Crie um ambiente virtual

Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Windows:

```powershell
python -m venv .venv
.venv\Scripts\activate
```

### 3. Instale as dependências

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Caso esteja configurando a integração com o Gemma 4, verifique se o SDK oficial está incluído nas dependências:

```bash
python -m pip install google-genai
```

### 4. Configure as variáveis de ambiente

Crie uma cópia do arquivo de exemplo:

```bash
cp .env.example .env
```

No Windows, você também pode copiar o arquivo manualmente.

Configure o `.env` com sua chave e o identificador do modelo:

```env
GEMINI_API_KEY=sua_chave_aqui
GEMMA_MODEL=gemma-4-26b-a4b-it
```

Gere sua chave no Google AI Studio:

https://aistudio.google.com/apikey

Consulte a documentação oficial para verificar os modelos disponíveis e os requisitos de acesso:

https://ai.google.dev/gemma/docs/core/gemma_on_gemini_api

**Nunca compartilhe sua chave de API nem envie o arquivo `.env` para o GitHub.**

## ▶️ Executando a aplicação

Com o ambiente virtual ativado:

```bash
streamlit run app.py
```

Abra no navegador o endereço local informado pelo Streamlit.

## 🧪 Testes

Para executar os testes automatizados:

```bash
python -m pytest -v
```

Os testes atuais cobrem cenários como:

- Mensagens vazias.
- Linguagem de urgência.
- Solicitações de informações sensíveis.
- URLs suspeitas.
- Extração de múltiplas URLs.
- Mensagens sem indicadores identificados.
- Validação do tipo de entrada.

A suíte inicial contém sete testes automatizados.

## 🔐 Segurança e privacidade

O PhishingLens está sendo desenvolvido com atenção às seguintes práticas:

- **Não acessar URLs extraídas:** a análise textual não exige abrir os links presentes na mensagem.
- **Proteger credenciais:** chaves de API devem ser armazenadas em variáveis de ambiente.
- **Tratar mensagens como conteúdo não confiável:** instruções presentes em mensagens analisadas não devem alterar o comportamento esperado da aplicação.
- **Evitar conclusões absolutas:** a classificação não garante que uma mensagem seja maliciosa ou segura.
- **Considerar o envio à API:** quando a integração com o Gemma 4 estiver ativa, o conteúdo enviado ao modelo será processado pelo serviço externo. Não utilize mensagens reais com senhas, tokens ou outros dados confidenciais durante os testes.

A análise por IA não substitui ferramentas especializadas de segurança nem a verificação independente de solicitações suspeitas.

## 🗺️ Roadmap

- [x] Implementar o primeiro analisador baseado em regras.
- [x] Criar testes automatizados para o núcleo de análise.
- [ ] Consolidar a interface com Streamlit.
- [ ] Integrar o Gemma 4 pela API Gemini.
- [ ] Combinar os resultados locais com a análise contextual da IA.
- [ ] Melhorar a apresentação das evidências e recomendações.
- [ ] Ampliar a cobertura de testes.
- [ ] Documentar limitações e avaliar a qualidade das classificações.

## 🤝 Contribuição

Contribuições são bem-vindas!

1. Faça um fork do repositório.
2. Crie uma branch para sua alteração.
3. Implemente a melhoria e adicione testes quando necessário.
4. Execute os testes automatizados.
5. Abra um pull request descrevendo as mudanças.

## 📄 Licença

Este projeto utiliza a licença definida no arquivo `LICENSE`.

---

**PhishingLens** — análise de mensagens suspeitas com Python e inteligência artificial.
