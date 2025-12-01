# server

```` 
$ python3 -m venv .venv
$ ./.venv/bin/pip install -r requirements.txt
$ DEBUG=0 HOST="0.0.0.0" PORT=5666 BLOCK_SIZE=4096 ./.venv/bin/python [server_file]
# Or make sure to setup the ENV variables mentioned below
# source ./.env
# ./.venv/bin/python [server_file]
````

```` 
HOST="0.0.0.0"
PORT="5666"
BLOCK_SIZE="4096"
DEBUG="0"
```` 
