# 自作NAT
技術評論社:ルーター自作でわかるパケットの流れ

(https://gihyo.jp/book/2011/978-4-7741-4745-1)

のコードを参考に自作したNAT

Linux上で動作

# 使い方
- lib-janssonをインストール

- リポジトリをクローン
```sh
git clone https://github.com/yushoyamaguchi/yama_nat.git
```
- conf.jsonに設定を書き込む
    - WAN_interfaceの項目にWAN側のインターフェース名を書き込む(1つのみ)
    - LAN_interfacesの項目にLAN側のインターフェース名を書き込む(複数可)
    - routing_tableの項目にルーティング情報を書き込む
        - next_hopにWAN側のネクストホップを、subnet_maskに0を設定したものを必ず入れる

```json
    "routing_table":[
        {
            "dest_addr":"0.0.0.0",
            "subnet_mask":"0",
            "next_hop":"10.255.1.1"
        }
    ]
```    

- makeを実行する

- yama_routerを実行する
