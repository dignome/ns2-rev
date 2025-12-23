Just a PoC vibe-coded NS2 (Natural Selection 2 - the game) netcode dumper.

What it does:

Scans a wireshark saved pcap network capture of traffic between the client and server extracting any information available to the client sent by the server.

Capable of dumping any kind of Network Message (as long as they are in the schema - and if not you can add to it).

Is capable of extracting and dumping as wav audio the speex encoded voice chat packets sent by the server to the client including spatial (type 2 or 3).

There is currently no easy way of creating the schema definition file - it is defined on the lua side.  Have included a basic schema from stock NS2 definitions.

What it doesn't do:

Does not currently parse state snapshots including client movement updates or server sent snapshots (future work)

See notes for more information.



Also useful is the udpreplaygo repo - can use it to replay a game from client connect to map change (if it doesn't crash).
https://github.com/dignome/udpreplaygo


This project is intended for **educational, research, and interoperability purposes only**.

It is not designed or intended to be used for:
- Cheating in online games
- Circumventing security or anti-cheat mechanisms
- Harassment, exploitation, or abuse of services or users
- Violating any software license, terms of service, or applicable laws

By using this repository, you agree to use it responsibly and ethically.
