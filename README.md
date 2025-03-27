> [!IMPORTANT]
>
> 针对去中心化的messager进行分析，进行一个全面的分析，并从多维度的角度分析。题目可为：《不同decentralized messagers的测量与安全分析》

```python
1. 针对不同decentralized messagers，分析其不同结构、原理；
   a. 与Signal的对比：上面的去中心化即时通讯软件与中心化的Signal软件的异同，如何体现出去中心化性质
   b. 找到或者给出解释：针对去中心化消息应用的通用性/特性的东西进行测量；
   c. WHOIS，词云，
   d. 数据获取程序，撰写可以并行执行任务的程序，包装成一个通用性的数据获取框架

2. 根据不同decentralized messagers的架构，提出一种通用的爬虫方法，获取不同messagers的生态数据，分别展开大规模测量；

3. 针对不同decentralized encrytion protocols，提出一套具有comprehensive的formal analysis method，分别展开安全协议分析（并提出相关的mitigations？）

4. 5个典型（多数与Signal有很深的渊源）：Matrix, Berty, Status, Atox，Jami

5. 可以投的会议、期刊：
ASE 2025（ddl在2025.5.30，8月中旬给意见）、WINE 2025（ddl大约在2025.7月中旬，9月中旬给结果）、
INFOCOM 2026（ddl大约在2025.7月底）、ICSE2026（ddl在2025.7.11/7.18）、FSE 2026（ddl在2025.9月）、
ISSTA 2026（ddl在2025.10月底）、WWW 2026（ddl大约在2025.10月中旬）
```

--------------------------

1. **Matrix** (Olm Protocol, 参考Signal Double ratchet协议) 

   ```python
   1. 端到端加密协议与Signal双棘轮协议有相似之处，Megolm协议的分析是我们之前所未做的
   
   2. 通过API获取数据，先获取可以readable的public rooms，在获取这些rooms中的用户id
   a) Lists the public rooms on the server.
   curl -X POST "https://matrix.org/_matrix/client/v3/publicRooms?server=ipfs.io" -H "Accept: application/json" -H "Authorization: Bearer syt_bGVlaG9v_aHvkQBdDkFkBQdRXIMlV_0r0TKF" -H "Content-Type: application/json" -d '{"include_all_networks":false}'
   
   b) Start the requesting user participating in a particular room.
   curl -X POST "https://matrix.org/_matrix/client/v3/join/%21gjVWrdgtzJFPBtcgww:matrix.org?server_name=matrix.org&server_name=elsewhere.ca&via=matrix.org&via=elsewhere.ca" -H "Accept: application/json" -H "Authorization: Bearer syt_bGVlaG9v_aHvkQBdDkFkBQdRXIMlV_0r0TKF" -H "Content-Type: application/json"
   
   c) Gets the list of currently joined users and their profile data.
   curl -X GET "https://matrix.org/_matrix/client/v3/rooms/%21GFUhHfvhuHnmIduHUu:ipfs.io/joined_members" -H "Accept: application/json" -H "Authorization: Bearer syt_bGVlaG9v_aHvkQBdDkFkBQdRXIMlV_0r0TKF"
   
   d) Stop the requesting user participating in a particular room.
   curl -X POST "https://matrix.org/_matrix/client/v3/rooms/%21gjVWrdgtzJFPBtcgww:matrix.org/leave" -H "Accept: application/json" -H "Authorization: Bearer syt_bGVlaG9v_aHvkQBdDkFkBQdRXIMlV_0r0TKF" -H "Content-Type: application/json"
   
   e) homeserver域名转IP地址：https://federationtester.matrix.org/
   ```

2. **Berty** （Wesh Protocol）【done】

   ```python
      1. 获取方式：通过"berty peers"命令可以获取不同节点的IP地址，但是其他的用户信息却难以获取
      有CLI版本，可以通过该模式获取数据：https://github.com/berty/berty/tree/master/go
      Wesh协议安全分析（文档、Git Repos）：Wesh协议的重要角色以及安全协议流程；利用Proverif对构建的不同协议进行formal analysis
   
      2. 其他信息：
      https://berty.tech/docs/protocol/
      加密部分参考Signal Symmetric-key ratchet协议；但Joining a Group提出了新的机制，包括：innovation，exchanging messages
   ```

3. **Status** (Waku Node，end-to-end encryption by X3dh, decentralized by Waku protocol)【done】

     ```python
     1. Waku采用的是noise协议进行密钥交换，Status采用X3DH协议保障端到端加密的安全，获取Waku网络的方式：运行以下命令：
     ./build/wakunode2 --rendezvous=false --dns-discovery=true --dns-discovery-url="enrtree://AIRVQ5DDA4FFWLRBCHJWUWOO6X6S4ZTZ5B667LQ6AJU6PEYDLRD5O@sandbox.waku.nodes.status.im" --discv5-discovery=true --discv5-enr-auto-update=true --relay-peer-exchange=true | tee waku.2025.03.12.log > /dev/null
     再通过sudo tcpdump -i eth0 udp port 9000 | tee waku.2025.03.12.txt > /dev/null获取交互的IP或者DNS。
     
     2. 其他连接：
     https://status.app/specs/status-1to1-chat；https://rfc.vac.dev/waku/standards/application/53/x3dh/
     https://zealous-polka-dc7.notion.site/Building-ca1db4fb3baf4f15bab8da717832b743
     https://github.com/status-im/status-go/blob/develop/_docs/how-to-build.md
     https://github.com/status-im/status-go/tree/develop/cmd/status-cli
     https://github.com/status-im/status-go/tree/develop/cmd/status-backend
     https://waku-org.github.io/waku-rest-api/
     https://fleets.status.im/
     ```

4. [Tox](https://github.com/TokTok/c-toxcore)（目前方案暂定获取开源数据-数据量小）【done】


> ```python
> 1. 官方文档：https://toktok.ltd/spec；tox nodes：https://nodes.tox.chat/json；The Tox Reference：https://zetok.github.io/tox-spec/；
> 2. 采用libsodium进行加密和认证
> 3. 安装Tox node：https://wiki.tox.chat/users/nodes；https://wiki.tox.chat/users/runningnodes
> ```

5. [Jami](https://jami.net/zh/)（opendht）【done】


> ```python
> 0. https://github.com/savoirfairelinux
> 1. https://git.jami.net/savoirfairelinux/dhtnet/-/blob/master/BUILD.md；https://github.com/savoirfairelinux/opendht/wiki/Running-a-node-with-dhtnode；
> 2. https://docs.jami.net/en_US/user/lan-only.html#bootstrapping
> 3. cd /home/ubuntu/download/opendht/build, and run the binary command
> 4. 采用python脚本，扫描opendht节点并保存：/home/ubuntu/work/opendht/python/tools: python3 schedule_scanner.py
> ```
>
> [!IMPORTANT]

>   ```python
> 1. 用户规模（用户画像，行为分析，等）--测量
> 2. 数据存储模式（策略）--测量
> 3. 交互方式（communication的方式，寻址，群组交互，等）--测量
> 4. 安全协议（端到端加密协议，等）--安全分析
> 4. 不同decentralized messager存在的协议漏洞？
> 4. 分别针对与Direct Messaging以及Group Messaging做安全分析？比如，对Matrix、Berty的Group和Direct协议进行分析
>   ```
