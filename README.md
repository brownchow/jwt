# Go 实现 JWT



## 原理

以前是用 cookie/ session，后来变成 JWT。

以前用户每次访问都会带上 SessionID，服务器校验 SessionID判断是同一个用户，**用户信息保存在服务端**，服务端需要查表找到用户

JWT 是服务端生成信息，并用自己的密钥（key）签名数据，**服务端不存数据**，JWT 包含了用户的所有信息，**用户信息保存在客户端**，服务端不做任何存储，**这意味着你可以用一个 JWT，请求多个服务器，不会存在一个服务器有客户端Session，但另一个服务器没有客户端Session**

```C
+---------+                       +----------+
|  Client |                       |  Server  |
|         |                       |          |
+---+-----+                       +-----+----+
    |                                   |
    |    POST /user/login               |
    |    {email, password}              |
    +---------------------------------->+ Store User
    |                                   | Session
    |    Send SessionID as cookie       | in Server
    <-----------------------------------+ Memory
    |                                   |
    |                                   |
    | Send Requsest with SessionID(Cookie)
    +----------------------------------->
    |                                   | get Usedrd
    |     Send Respopnse                | from session
    <-----------------------------------+ based on id
    |                                   | and verify them
    |                                   |
    |                                   |
    |                                   |
    |                                   |



+---------+                       +----------+
| Client  |                       |  Server  |
|         |                       |          |
+---+-----+                       +-----+----+
    |                                   |
    |      POST /user/login             |
    |      {email, password}            |
    +---------------------------------->+
    |                                   | Create JWT
    |     Send JWT to browser           | for user with
    <-----------------------------------+ secret
    |                                   |
    |                                   |
    |     send Request with JWT         |
    +-----------------------------------> Verify JWT
    |                                   | Signature
    |     Send Response                 | and Get User
    <-----------------------------------+ From JWT
    |                                   |
    |                                   |
    |                                   |
    |                                   |
    |                                   |
        
```



## 使用场景

```c
Bank                        Retirement

+------------+              +------------+
|            |              |            |
|            |              |            |
|            |              |            |
|            |              |            |
|            |              |            |
|            |              |            |
|            |              |            |
|            |              |            |
+----^-------+              +-------^----+
     |                              |
     |                              |
     |                              |
     +---------+           +--------+
               |           |
               |           |
               |           |
               |           |
         +-----+-----------+--------+
         |                          |
         |     Client(Broswer)      |
         |                          |
         +--------------------------+

```



访问多个服务器，只要服务器上存储**相同的 secret key**，就可以认证成功，不需要每次都登录



## 总结

### 编码的过程

分别对Header，payload  序列化之后，再base64编码，



### HMAC 算法

Hash Message Authentication Code

需要用到密钥



## JWT 的优缺点





## reference

https://github.com/robbert229/jwt

https://jwt.io/

https://www.youtube.com/watch?v=7Q17ubqLfaM

https://www.youtube.com/watch?v=rxzOqP9YwmM

https://www.youtube.com/playlist?list=PLZlA0Gpn_vH8DWL14Wud_m8NeNNbYKOkj