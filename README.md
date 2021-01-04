# pDiem

1. Clone Diem source code
```
git clone https://github.com/diem/diem.git
```

2. Compile Diem node & cli
```
cd diem
cargo build --release
cargo build --release -p cli
```

3. Run Diem node
```
./target/release/diem-node --test
```
Got mint.key and waypoint from log.

4. Run Diem cli to create account, mint, transfer, etc.
```
./target/release/cli -c TESTING -m /tmp/8b8722bcbee2c9b36df7612038cda0eb/mint.key -u http://127.0.0.1:8080 --waypoint 0:51b1864a4a00aec0a525334026c89c3dcdc6c3e92809ef130a96aff191869a49
```

5. Clone pDiem source code and compile
```
git clone https://github.com/goldenfiredo/pDiem.git
cd pDiem
cargo build --release
```

6. Run pDiem to sync specified accounts' transactions:
```
./target/release/pDiem 
```
You can also connect official endpoint instead of running local node:
```
./target/release/pDiem --diem-rpc-endpoint https://testnet.diem.com/v1

diem node commit :  e927ae5