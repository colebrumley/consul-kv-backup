# kv-backup
_Backup Consul's KV Store with TLS and HTTP Basic auth support_

I couldn't find a Consul KV backup/restore tool that supported all of the TLS/auth options I needed out of the box.  Here's the beginnings of one in go.

This doesn't have Consul ACL support at the moment, feel free to add it!

```
NAME:
   kv-backup - Back up Consul's KV store

USAGE:
   kv-backup [global options] command [command options] [arguments...]

VERSION:
   0.1

COMMANDS:
   backup	Dump Consul's KV database to a JSON file
   restore	restore a JSON backup of Consul's KV store
   help, h	Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --cacert, -r 		Client CA cert [$CONSUL_CA_CERT]
   --prefix "/"			Root key prefix [$CONSUL_PREFIX]
   --cert, -c 			Client cert [$CONSUL_CERT]
   --key, -k 			Client key [$CONSUL_KEY]
   --addr, -a "127.0.0.1"	Consul address (No leading 'http(s)://') [$CONSUL_HTTP_ADDR]
   --scheme, -s "http"		Consul connection scheme (HTTP or HTTPS) [$CONSUL_SCHEME]
   --port, -p "8500"		Consul port [$CONSUL_PORT]
   --insecure, -i		Skip TLS host verification [$CONSUL_INSECURE]
   --username, --un 		HTTP Basic auth user [$CONSUL_USER]
   --password, --pw 		HTTP Basic auth password [$CONSUL_PASS]
   --help, -h			show help
   --version, -v		print the version
```
For TLS connections, kv-backup will load the system root CAs on most mainstream Linux distros. If `--cacert` is defined, this CA will be added to the list of root CAs.

```
NAME:
   backup - Dump Consul's KV database to a JSON file

USAGE:
   command backup [command options] [arguments...]

OPTIONS:
   --outfile, -o 	Write output to a file [$CONSUL_OUTPUT]
```

Skipping the `-o` flag on `backup` will pretty-print the json to stdout

```
NAME:
   restore - restore a JSON backup of Consul's KV store

USAGE:
   command restore [arguments...]
```

To restore, pass the name of a backup file (no stdin support yet)
