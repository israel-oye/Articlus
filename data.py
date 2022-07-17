import requests

END_POINT = "https://api.npoint.io/5772056d33771fc33f71"

ARTICLES = requests.get(END_POINT).json()

def get_articles():

    return ARTICLES