import requests
import os
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("WEATHER_API_KEY")


def obter_previsao(cidade):
    if not API_KEY:
        print("Erro: A chave da API não foi configurada. Verifique o arquivo .env.")
        return None

    url = f"http://api.weatherapi.com/v1/current.json?key={API_KEY}&q={cidade}&lang=pt"
    try:
        resposta = requests.get(url)
        resposta.raise_for_status()  
        # Levanta uma exceção para códigos de status de erro (4xx ou 5xx)
        dados = resposta.json()
        temperatura = dados['current']['temp_c']
        condicao = dados['current']['condition']['text']
        return temperatura, condicao
    except requests.exceptions.RequestException as e:
        print(f"Erro ao obter a previsão do tempo: {e}")
        return None
    except (KeyError, TypeError) as e:
        print(f"Erro ao processar a resposta da API: {e}")
        return None


if __name__ == "__main__":
    cidade = input("Digite o nome da cidade: ")
    previsao = obter_previsao(cidade)
    if previsao:
        temperatura, condicao = previsao
        print(f"A temperatura em {cidade} é {temperatura}°C com {condicao}.")
    else:
        print("Não foi possível obter a previsão do tempo.")