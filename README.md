> [!IMPORTANT]
>
> 针对去中心化的messager进行分析，进行一个全面的分析，并从多维度的角度分析。题目可为：《不同decentralized messagers的测量与安全分析》

```python
1. 针对不同decentralized messagers，分析其不同结构、原理；
   a. 与Signal的对比：上面的去中心化即时通讯软件与中心化的Signal软件的异同，如何体现出去中心化性质

2. 根据不同decentralized messagers的架构，提出一种通用的爬虫方法，获取不同messagers的生态数据，分别展开大规模测量；

3. 针对不同decentralized encrytion protocols，提出一套具有comprehensive的formal analysis method，分别展开安全协议分析（并提出相关的mitigations？）

4. 4个典型（多数与Signal有很深的渊源）：Matrix, Berty, Status, Bluesky

5. 可以投的会议、期刊：
	ASE 2025（ddl在2025.5.30，8月中旬给意见）、WINE 2025（ddl大约在2025.7月中旬，9月中旬给结果）、INFOCOM 2026（ddl大约在2025.7月底）、
	[ICSE2026](https://conf.researchr.org/home/icse-2026)（ddl大约在2025.8月初）、FSE 2026（ddl在2025.9月）、ISSTA 2026（ddl在2025.10月底）、WWW 2026（ddl大约在2025.10月中旬）
```

--------------------------

1. **Matrix** (Olm Protocol, 参考Signal Double ratchet协议) 

   1. 端到端加密协议与Signal双棘轮协议有相似之处

   1. > [!IMPORTANT]
      >
      > - [x] **通过API获取数据**

2. **Berty** (Wesh Protocol, )

   1. ```python
      https://berty.tech/docs/protocol/
      
      当前还没有采用Berty Protocol，而是OrbitDB；
      
      加密部分参考Signal Symmetric-key ratchet协议；但Joining a Group提出了新的机制，包括：innovation，exchanging messages
      ```

   2. > [!IMPORTANT]
      >
      > - [x] **有CLI版本，可以通过该模式获取数据**：https://github.com/berty/berty/tree/master/go

3. **Status** (end-to-end encryption by X3dh, decentralized by Waku protocol)

   - [x] 手动构建获取部分的数据：

     ```
     Google Play 下载量超过100万
     https://status.app/help/profile#security-and-privacy
     https://status.app/specs/status-1to1-chat；https://rfc.vac.dev/waku/standards/application/53/x3dh/
     
     https://zealous-polka-dc7.notion.site/Building-ca1db4fb3baf4f15bab8da717832b743
     
     CLI：
     https://github.com/status-im/status-go/blob/develop/_docs/how-to-build.md
     https://github.com/status-im/status-go/tree/develop/cmd/status-cli
     
     通过HTTP访问完整的status-go API：
     https://github.com/status-im/status-go/tree/develop/cmd/status-backend
     
     The default password used by Status App and our mailservers is status-offline-inbox: https://fleets.status.im/
     
     ```

4. **BlueSky** (decentralized, 其message功能还未完善)

   - [x] 如何获取messaging数据：Blusky提供的API接口

     ```
     1. https://docs.bsky.app/docs/advanced-guides/api-directory
     2. https://medium.com/@stephane.giron/post-and-get-messages-with-bluesky-social-api-and-google-apps-script-1cf76cd9c4cd
     3. https://github.com/dmoggles/blueskysocial
     4. https://www.ayrshare.com/complete-guide-to-bluesky-api-integration-authorization-posting-analytics-comments/
     5. 参考文章：Looking AT the Blue Skies of Bluesky
     ```

> [!IMPORTANT]
>
> What we should do: 
>
> 1. 用户规模（用户画像，行为分析，等）--测量
>
> 2. 数据存储模式（策略）--测量
>
> 3. 交互方式（communication的方式，寻址，群组交互，等）--测量
>
> 4. 安全协议（端到端加密协议，等）--安全分析
>
>     a. 不同decentralized messager存在的协议漏洞？

1. ~~**Session** (Session end-to-end encryption protocol, decentralised storage severs by lokinet)~~

   1. ```
      Google Play 下载量超100万，具有Whitepaper
      
      GitHub源码forked from Signal
      ```

   2. - [ ] **无CLI版本应用，但可以通过注入log代码至session-desktop，并重建**（未完成）：https://github.com/session-foundation/session-desktop/blob/unstable/CONTRIBUTING.md

2. ~~XMTP (decentralized, end-to-end encryption， MLS)~~

3. Mastodon（暂不支持direct message）

