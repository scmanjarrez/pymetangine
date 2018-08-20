import requests
import sys
import os

if len(sys.argv) != 3:
    print("Usage: {} md5_file output_folder".format(sys.argv[0]))
    sys.exit()

if os.path.exists(sys.argv[2]) and not os.path.isdir(sys.argv[2]):
    print("Output folder is not a directory")
    sys.exit()

if not os.path.exists(sys.argv[2]):
    os.mkdir(sys.argv[2])

url = "https://malshare.com/api.php?api_key=API&action=getfile&hash=HASH"

with open('malshare_apikey', 'r') as f:
    url = url.replace('API', f.read().strip())

md5_list = []
with open(sys.argv[1], 'r') as f:
    md5_list = f.read().splitlines()

for md5 in md5_list:
    r = requests.get(url.replace('HASH', md5))
    with open(os.path.join(sys.argv[2], md5 + ".bin"), "wb") as f:
        f.write(r.content)


