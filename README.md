# Kerberos
基于SM算法改进的Kerberos身份认证系统

系统依赖库：[duanhongyi](https://github.com/duanhongyi)/[**gmssl**](https://github.com/duanhongyi/gmssl)


**系统架构图：**

![pic](https://github.com/eW1z4rd/Kerberos/tree/master/pic/pic.png)

**其中：**

1. AS_REQ = { timestamp } Kclt, UserA, nonce, iv

2. Challenge = challenge_msg

3. Response = { response_msg }hash

4. TGT = { UserA, Kclt-kdc } Kkdc

   AS_REP = TGT, { Kclt-kdc, timestamp, nonce } Kclt, iv

5. TGS_REQ = TGT, { UserA, timestamp } Kclt-kdc, ResourceB

6. Ticket = { UserA, Kclt-srv } Ksrv

   TGS_REP = { Kclt-srv } Kclt-kdc, Ticket

7. CS_REQ = { UserA, timestamp } Kclt-srv, Ticket

8. CS_REP = { timestamp } Kclt-srv

