# peer-node-info

ピアノードのノード情報を取得する

# 準備

## SymbolSDK をインストール

```
pip install symbol-sdk-python pyopenssl
```

## peer-node-info と certtool をクローン

```
git clone https://github.com/ccHarvestasya/peer-node-info.git
git clone https://github.com/ccHarvestasya/symbol-node-configurator.git
```

## CA プライベートキー生成

```
cd peer-node-info
openssl genpkey -algorithm ed25519 -outform PEM -out ca.key.pem
```

## 証明書の生成

```
python ../symbol-node-configurator/certtool.py --working cert --name-ca "my cool CA" --name-node "my cool node name" --ca ca.key.pem
cat cert/node.crt.pem cert/ca.crt.pem > cert/node.full.crt.pem
```

# 実行

```
python main.py 11.dusanjp.com
```

## 通信ポート変更されている場合

引数にポート番号を指定

```
python main.py 03.symbol-node.com 7913
```

# 参考

- [Chatting with Peers for Fun and Profit - Symbol Blog](https://symbolblog.com/developer-guides/chatting-with-peers-for-fun-and-profit/)
