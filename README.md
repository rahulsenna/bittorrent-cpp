# BitTorrent-CPP

A simple **BitTorrent CLI client** written in C++.
It supports downloading from both **`.torrent` files** and **magnet links**, with piece-level control for magnet downloads.

---

## ✨ Features

* Download files using a `.torrent` file.
* Download specific pieces from a magnet link.
* Command-line interface (no GUI).
* Lightweight and minimal dependencies.

---

## ⚡ Usage

### Build

```bash
git clone https://github.com/rahulsenna/bittorrent-cpp.git
cd bittorrent-cpp
mkdir build && cd build
cmake ..
make
```

The binary will be available in the `build/` directory.

---

### Commands

#### 1. Download with `.torrent` file

```bash
./bittorrent-cpp download -o out_file sample.torrent
```

* `-o out_file` → output file path
* `sample.torrent` → path to the torrent file

---

#### 2. Download specific piece from a magnet link

```bash
./bittorrent-cpp magnet_download_piece -o out_file "<magnet-link>" <piece_index>
```

* `-o out_file` → output file path
* `<magnet-link>` → the magnet URI
* `<piece_index>` → index of the piece to download

---

## 📂 Example

```bash
./bittorrent-cpp download -o ubuntu.iso ubuntu.torrent
```

```bash
./bittorrent-cpp magnet_download_piece -o chunk.bin "magnet:?xt=urn:btih:..." 5
```

---

## 🚧 Status

This project is under active development.
Currently supports:

* Parsing `.torrent` files
* Parsing magnet URIs
* Downloading via BitTorrent protocol

Planned improvements:

* Multi-piece downloads for magnet links
* Peer management & choking/unchoking
* Upload/seeding support

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!
Feel free to fork the repo and submit a PR.

---

## 📜 License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.
