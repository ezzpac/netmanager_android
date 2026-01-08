# Guia para Gerar o APK do NetManager Android

Você agora tem uma pasta dedicada chamada `NetManager_Android` com os arquivos adaptados para rodar o servidor Flask diretamente no seu celular.

## Opção 1: Pydroid 3 (A mais simples - Sem compilação)
Se você quer apenas rodar o app no seu celular agora sem passar pelo processo de criar um arquivo `.apk`, esta é a melhor forma:

1.  Instale o app **Pydroid 3** da Play Store no seu celular.
2.  Copie a pasta `NetManager_Android` para a memória do seu celular.
3.  No Pydroid 3, abra o arquivo `main.py`.
4.  Vá em "Pip" e instale as dependências: `flask`, `flask-sqlalchemy`, `openpyxl`.
5.  Clique no botão "Play" (ícone amarelo) e o app abrirá no navegador do celular.

---

## Opção 2: GitHub Actions (Geração de APK Automática)
Se você quer o arquivo `.apk` mas não quer configurar nada manual no Colab ou Linux:

1.  Crie um repositório no seu **GitHub** (pode ser privado).
2.  Suba os arquivos da pasta `NetManager_Android`.
3.  Eu posso criar um arquivo chamado `.github/workflows/android.yml` para você.
4.  Sempre que você atualizar o código, o GitHub criará o `.apk` sozinho e deixará o link para download pronto.

---

## Opção 3: Google Colab (O método padrão)
Este é o método que já descrevi, usando o Buildozer. É o mais comum para quem quer gerar o arquivo `.apk` manualmente uma única vez.

### Passo a Passo no Google Colab:
1.  Acesse o [Google Colab](https://colab.research.google.com/).
2.  Carregue (Upload) a sua pasta `NetManager_Android` (comprima-a em .zip primeiro).
3.  No Colab, execute:

```python
# Instalar buildozer
!pip install buildozer
!apt-get install -y libexport-perl libglib2.0-dev libgstreamer1.0-dev

# Iniciar compilação
!buildozer android debug
```

4.  Ao final, o arquivo `.apk` estará dentro da pasta `bin/` no Colab. Baixe-o para o seu computador e envie para o seu celular.

## Notas importantes:
*   **Importação de XLSX**: Certifique-se de dar permissão de armazenamento ao app no celular para que ele consiga ler os arquivos que você deseja importar.
*   **Primeira Inicialização**: O app pode demorar alguns segundos a mais para abrir na primeira vez, pois ele estará configurando o banco de dados interno.

**Dica**: Se você tiver o WSL instalado no Windows, também pode rodar o `buildozer android debug` localmente.
