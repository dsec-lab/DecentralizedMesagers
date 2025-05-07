> [!IMPORTANT]
>
> Perform an in-depth analysis of decentralized messaging platforms from multiple dimensions, including architecture, performance, and security.
> "Unveiling the Decentralized Messaging Landscape: A Large-Scale Measurement and Security Perspective".

```python
1. 针对不同decentralized messagers，分析其不同结构、原理；
   a. 与Signal的对比：上面的去中心化即时通讯软件与中心化的Signal软件的异同，如何体现出去中心化性质
   b. 找到或者给出解释：针对去中心化消息应用的通用性/特性的东西进行测量；
   c. WHOIS，词云，
   d. 数据获取程序，撰写可以并行执行任务的程序，包装成一个通用性的数据获取框架

2. Based on the architectures of various decentralized messengers, a unified crawling approach is proposed to collect ecological data from each platform and conduct large-scale measurements accordingly.

3. A comprehensive formal analysis approach is proposed to evaluate the security of various decentralized encryption protocols, identifying potential vulnerabilities and recommending corresponding mitigation strategies.

4. 5个典型（多数与Signal有很深的渊源）：Matrix, Berty, Status, Atox，Jami

5. 可以投的会议、期刊：
	WINE 2025（ddl大约在2025.7月中旬，9月中旬给结果）、INFOCOM 2026（ddl大约在2025.7月底）、ICSE2026（ddl在2025.7.11/7.18）、FSE 2026（ddl在2025.9月）、ISSTA 2026（ddl在2025.10月底）、WWW 2026（ddl大约在2025.10月中旬）
```

--------------------------

1. **Matrix** (Olm Protocol, 参考Signal Double ratchet协议) 【done】

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
https://status.app/specs/status-1to1-chat；https://rfc.vac.dev/waku/standards/application/53/x3dh/；https://github.com/waku-org/specs/blob/master/standards/application/noise.md
### 可能存在漏洞的点：https://specs.status.im/spec/2#x3dh-prekey-bundles
Status 不会发布一次性密钥 OPK 或执行包含它们的 DH，因为 Status 实现中没有中央服务器。
客户端应该每 24 小时重新生成一个新的 X3DH 预密钥包。这可以采用惰性方式进行，即如果客户端在此时间段后仍未上线，则不会重新生成或广播密钥包。当前捆绑包应间歇性地在特定于其身份密钥 {IK}-contact-code 的 Whisper/Waku 主题上广播。此操作可以每 6 小时进行一次。

威胁模型：https://rfc.vac.dev/waku/standards/core/11/relay#adversarial-model
https://fleets.status.im/
```

4. [Jami](https://jami.net/zh/)（opendht）【done】


> ```python
> 0. https://github.com/savoirfairelinux
> 1. https://git.jami.net/savoirfairelinux/dhtnet/-/blob/master/BUILD.md；https://github.com/savoirfairelinux/opendht/wiki/Running-a-node-with-dhtnode；
> 2. https://docs.jami.net/en_US/user/lan-only.html#bootstrapping
> 3. cd /home/ubuntu/download/opendht/build, and run the binary command
> 4. 采用python脚本，扫描opendht节点并保存：/home/ubuntu/work/opendht/python/tools: python3 schedule_scanner.py
> ```

5. [Tox](https://github.com/TokTok/c-toxcore)（目前方案暂定获取开源数据-数据量小）【done】


> ```python
> 1. 官方文档：https://toktok.ltd/spec；tox nodes：https://nodes.tox.chat/json；The Tox Reference：https://zetok.github.io/tox-spec/；
> 2. 采用libsodium进行加密和认证
> 3. 安装Tox node：https://wiki.tox.chat/users/nodes；https://wiki.tox.chat/users/runningnodes
> ```
>
>   ```python
> 数据列表：
> 1. 地域性数据（city、region、country、经纬度），归属组织数据（org、asn、ISP、CIDR），hostname
> 2. IP reputation数据（malicious、malicious_label、），IP communication数据（XXX），IP referrer files数据（popular_threat_classification、）
> 3. Shodan数据（opened port、tags、domains、product、version、server host key algorithms，vulns）
> 4. CVE数据（assignerShortName、problemTypes（CWE）、affected.vendor）
> 
> 
> 测量TODO：
> 0. 测量的目的是要围绕分析这几种不同的去中心化messagers之间的差异性和共性，包括测量和安全等方面；
>   |-- 不同decentralized messagers之间的架构比较、探讨
>   |-- 交互方式（communication的方式，寻址，群组交互，等）
>   |-- 数据存储模式（策略）
>   |-- 安全协议（端到端加密协议，等）、
> 1. 物理与网络地理测量（部署性）：分析 IP 地址的地理分布，寻找特定地区的安全威胁模式。
>   |-- ASN、ISP，是否集中在某些国家，是否依赖某个区域（如欧美服务器多，中国少）
>   |-- 住宅/数据中心 IP：测量数据中心 IP 是否存在大量端口暴露情况。
>   |-- VPN代理情况
> 2. IP 关系网络分析（行为性）：利用图神经网络（GNN） 识别Node节点IP之间的关联性。
>   |-- 相同 ASN 或国家的 IP 是否存在相似行为？相同 C2 服务器的 IP 是否共同执行攻击？
>   |-- 构建通信或邻接图：IP归属同一ASN/国家、相似端口开放行为、是否连接相同的其他节点（共同邻居）
> 3. 端口暴露情况测量（安全性、隐私性）：评估 IP 的开放端口情况，分析潜在的网络攻击风险，设备类型。
>   |-- 默认凭证风险：Shodan 可能会显示某些设备仍然使用默认密码。
>   |-- 某个 IP 段（CIDR）暴露大量 RDP 端口，可能被勒索软件攻击者利用。
>   |-- 加密情况、P2P端口、是否使用 Tor、VPN、Proxy 等隐藏真实 IP（隐私性）
> 4. CVE 漏洞影响测量（安全性、隐私性）：节点与漏洞对应情况、设备类型分析、影响产品、漏洞类型
>   |-- 高危 CVE（CVSS 评分 > 8）
>   |-- IP地址与CVE之间的对应，构建 CVE 传播模型，查看某个漏洞是否随着时间扩散到更多 IP
> 5. 恶意活动测量（安全性、隐私性）：分析 IP 是否出现在威胁情报数据库中，并进行威胁分类。
>   |-- Virustotal（恶意 IP）+ Shodan（端口、漏洞）构建 IP 关系图（GNN?）
>   |-- Virustotal（恶意 IP）+ IPInfo构建 IP 地理关系图
>   |-- 假设我们认为VT针对IP进行了打标签（正常、恶意）。是否可以利用这些节点的多方位特征信息（位置信息、开放端口、ISP、Shodan信息、暴露的vulns、加密算法、支持的 TLS/加密协议版本、认证方式、是否开放注册、认证算法、关联products、tag、等信息）构建GNN，通过已构建的GNN模型识别（训练集、测试集、验证集）。
>   |-- 甚至可以通过迁移学习的技术，在比如利用Matrix的数据进行训练，测试Berty网络的安全行，符合interoperability。
> 6. 协议安全分析
>   |-- 不同decentralized messager存在的协议漏洞（共性、差异性）
>   |-- 分别针对与Direct Messaging以及Group Messaging做安全分析？比如，对Matrix、Berty的Group和Direct协议进行分析
>   |-- 提出防御策略
> 7. 多设备安全分析（未来研究工作）
> 
> 发现与启示TODO：
> 1. 网络基础设施相关的见解：节点的地理与网络分布不均衡，大量节点托管在特定云服务商上
> 2. 安全暴露与威胁相关的见解：节点暴露高危端口，存在多个存在 CVE 漏洞的节点，节点被 VirusTotal 标记为恶意（节点可能被滥用，或者属于攻击基础设施的一部分），
> 3. 行为模式与图结构的洞察：节点之间存在可疑关联结构，某些节点行为与多数明显不同（PS：需对“离群节点”做进一步溯源分析，最好是能识别新型威胁手法）
>   |-- Shodan Hostnames/Tags	Shodan，附加标签，最好是能够发现是否为honeypot、蜜罐、botnet
> 4. 不同协议的安全性分析（端到端加密、多设备、群聊天）
    |-- Matrix提出的Olm协议（实际是对Signal的改进）；Berty提出的Wesh协议；Status对X3DH和Double Ratchet协议的删减
    |-- 密钥生成/派生协议、Handshake协议分析、消息端到端加密协议分析
>   ```
