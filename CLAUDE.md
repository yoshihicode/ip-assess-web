# ip-assess-web
IPアドレスを調査するサービス

## このツールの建付け
一次調査のツールであるip-assessをwebサービス化したもの。  
日本国内向け 

## 機能
- ip-assess.shの機能に加えて以下を追加する
- IPv6対応
- 診断結果をAIで評価
- 過去のIPの問い合わせ状況
    - 同じIPでいつどれくらい問い合わせがあったか 
- 多言語化(日本語・英語)
    - ただし、AIに関しては日本語がトークンを多く使うようであれば英語のみ
- Pingは打てないのでレーテンシはなし
- 複数のDNSBL

## ip-assess.shについて
github: https://github.com/yoshihicode/ip-assess
作成の経緯: docs/ip-assess_chat_summary.md

## インフラ
cloudfalre上で動かす
ただし無料枠

### 想定
```Mermaid
flowchart LR
    Browser["Browser"] --> Web["web Worker<br/>React SPA (Static Assets)"]
    Web -- "Service Bindings<br/>/api/*, /auth/*" --> Api["api Worker<br/>Hono (no public URL)"]
    Api --> D1[("D1")]
    Api --> Queue[["Queues"]]
    Queue --> Consumer["queue() handler"]
    Consumer --> AI["Workers AI"]
    Consumer --> D1
    Cron["Cron Triggers"] --> Queue
    Cache["Workers Cache"] -.-> Api
```
D1 で問い合わせをキャッシュ
                 
## UI
問合せをしてから各種調査をするために外部APIを叩く必要があります。 
そのためユーザーがIPを入力してから各種調査結果が順に表示されて処理が止まっていないように見せる。 
AIによる評価は無料枠の関係上1日20件程度におさえ、限度を超えたらCron/Queueで翌日に実行。  