import requests
url = "https://malshare.com/api.php?api_key=ce3a6a43bf306e2d713d33d93b8515287ed72fe8687942bb832d06141691a0ee&action=getfile&hash=HASH"

md5_list = []
with open('1000.md5', 'r') as f:
    md5_list = f.read().splitlines()

for md5 in md5_list:
    r = requests.get(url.replace('HASH', md5))
    with open(md5+".bin", "wb") as f:
        f.write(r.content)

