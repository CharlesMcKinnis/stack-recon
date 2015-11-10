#!/usr/bin/env python2
"""
Modified from http://kmkeen.com/socketserver/
"""

import socket
import pprint

def client(string):
    HOST, PORT = '172.24.16.68', 6386
    # SOCK_STREAM == a TCP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #sock.setblocking(0)  # optional non-blocking
    sock.connect((HOST, PORT))
    sock.send(string)
    reply = sock.recv(16384)  # limit reply to 16K
    sock.close()
    return reply

pp = pprint.PrettyPrinter(indent=4)

#assert client('2+2') == '4'
reply = client("INFO\n")
x=0
return_dict = {}
section = ""
for i in reply.splitlines():
    x += 1
    print "%3d %s" % (x,i)
    if i[0] == "#":
        # new section
        section = i.strip(' #')
        if not section in return_dict:
            return_dict[section] = {}
        continue
    key,value = i.split(':')
    key = key.strip()
    value = value.strip()
    return_dict[section][key] = value

pp.pprint(return_dict)
#print i

"""
# ./socket_redis_info.py
"""

"""
$1951
# Server
redis_version:2.8.23
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:b2a01b05f82d307a
redis_mode:standalone
os:Linux 2.6.32-573.1.1.el6.x86_64 x86_64
arch_bits:64
multiplexing_api:epoll
gcc_version:4.4.7
process_id:18553
run_id:908cf5785eada1b7b0c70926d87815acda532297
tcp_port:6386
uptime_in_seconds:67581
uptime_in_days:0
hz:10
lru_clock:4331073
config_file:/etc/redis/redis-obj3.conf

# Clients
connected_clients:1
client_longest_output_list:0
client_biggest_input_buf:0
blocked_clients:0

# Memory
used_memory:19159680
used_memory_human:18.27M
used_memory_rss:24211456
used_memory_peak:19204664
used_memory_peak_human:18.31M
used_memory_lua:36864
mem_fragmentation_ratio:1.26
mem_allocator:jemalloc-3.6.0

# Persistence
loading:0
rdb_changes_since_last_save:31954
rdb_bgsave_in_progress:0
rdb_last_save_time:1447104068
rdb_last_bgsave_status:ok
rdb_last_bgsave_time_sec:-1
rdb_current_bgsave_time_sec:-1
aof_enabled:0
aof_rewrite_in_progress:0
aof_rewrite_scheduled:0
aof_last_rewrite_time_sec:-1
aof_current_rewrite_time_sec:-1
aof_last_bgrewrite_status:ok
aof_last_write_status:ok

# Stats
total_connections_received:10924
total_commands_processed:1170677
instantaneous_ops_per_sec:0
total_net_input_bytes:107754103
total_net_output_bytes:7012513314
instantaneous_input_kbps:0.00
instantaneous_output_kbps:0.00
rejected_connections:0
sync_full:0
sync_partial_ok:0
sync_partial_err:0
expired_keys:416
evicted_keys:0
keyspace_hits:574692
keyspace_misses:554395
pubsub_channels:0
pubsub_patterns:0
latest_fork_usec:0

# Replication
role:master
connected_slaves:0
master_repl_offset:0
repl_backlog_active:0
repl_backlog_size:1048576
repl_backlog_first_byte_offset:0
repl_backlog_histlen:0

# CPU
used_cpu_sys:49.41
used_cpu_user:29.96
used_cpu_sys_children:0.00
used_cpu_user_children:0.00

# Keyspace
db1:keys=2596,expires=78,avg_ttl=4174538
"""