# kv-backup
_Backup Consul's KV Store with TLS and HTTP Basic auth support_

I couldn't find a Consul KV backup/restore tool that supported all of the TLS/auth options I needed out of the box.  Here's the beginnings of one in go.

This doesn't have Consul ACL support at the moment, feel free to add it!
