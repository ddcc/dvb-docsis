# Raw Traffic
## Server: Raw Traffic
1. `./dvb-docsis -t raw`

## Client: Raw Dump
1. `nc <ip> 7777 > data.mpg`
2. View the data
    * Wireshark > File > Open > `data.mpg`
    * `dvbsnoop -s ts -if data.mpg | less`

## Client: Raw Streaming
1. `nc <ip> 7777 > /dev/null`
2. Wireshark > Capture > Filter: `tcp.port == 7777` > Decode As > `MP2T`

# PCAP Traffic
## Server: PCAP Traffic
1. `./dvb-docsis -t pcap`

## Client: PCAP Dump
1. `nc <ip> 7777 > data.pcap`
2. Wireshark > File > Open > `data.pcap`

## Client: PCAP Streaming
1. `wireshark -k -i <(nc <ip> 7777)`
