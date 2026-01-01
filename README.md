# NS2 Netcode Dumper

This is a Proof of Concept (PoC) "vibe-coded" tool for analyzing *Natural Selection 2* network traffic.  Much of the code and even my understanding of how this works was derrived from the use of AI and RE tools.

## 📖 Overview
This tool scans a **Wireshark saved `.pcapng` file** to analyze traffic between the client and server. It extracts information sent by the server that is available to the client.

## ✨ Features

* **Traffic Analysis:** Scans `.pcap` dumps for relevant game packets.
* **Message Dumping:** Capable of dumping *any* kind of Network Message defined in the schema.
    * *Extensible:* If a message isn't in the schema, you can add it.
* **Audio Extraction:** Decodes Speex-encoded voice chat packets (sent by the server or client) and dumps them as `.wav` files.
    * *Spatial Support:* Dumps regular voice chat and also positional voice chat and positional/target (Type 2 or 3).

## ⚠️ Limitations & Future Work

* **State Snapshots:** Handles the snapshot header / any performance data / dumps state snapshots to json.  A separate program is currentlyy acting as a
    proof-of-concept state snapshot parser (entity-parse.py).
* **Authentication:** This tool does not act as a client; it cannot authenticate or join an NS2 server effectively.
* **There will be misunderstandings and bugs in this code as it is again devised from RE/AI.**

## 🛠️ Usage Notes
python ns2_net_dump.py spark-capture.pcapng &> output.txt

If using --dump-voice data is saved to data folder.

* **State snapshot data:**

Run ns2_net_dump.py which will produce the snapshots.json and the class table.

python entity-parse.py &> snapshot-output.txt

Add --trace_frames to see specific actions occurring in listed frames.  Can specify a single frame or a range like 0-25.

Currently just dumps the entity table at a specified frame in the code for demonstration purposes.

Unlike net message schema if you are missing even 1 schema definition for netclass or have incorrect schema then the data can not be trusted
and thus it aborts reading the bitstream.

### Schema Definitions
There is currently no automated way to create the schema definition file (that I'm willing to share), as it is defined on the Lua side of the game engine.
* A **basic schema** derived from stock NS2 definitions is included in this repo.

### Related Tools
This tool pairs well with **udpreplaygo**, which can replay a game session from client connection to map change.
* [View udpreplaygo on GitHub](https://github.com/dignome/udpreplaygo)

---

## ⚖️ Disclaimer

> [!WARNING]
> **Educational Use Only**

This project is intended for **educational, research, and interoperability purposes only**.

It is not designed or intended to be used for:
* Cheating in online games
* Circumventing security or anti-cheat mechanisms
* Harassment, exploitation, or abuse of services or users
* Violating any software license, terms of service, or applicable laws

**By using this repository, you agree to use it responsibly and ethically.**
