# HeartLink 云端：Linux、1Panel 与雷池 WAF 部署

HeartLink 云端是 Linux 通用的 Rust HTTP 服务，负责账户注册/登录、邮箱或手机验证码找回、登录会话、设备撤销和不透明密文同步。SSH、SFTP 和 RDP 流量仍由客户端直连目标服务器；云端同步密码、SSH 密码、私钥、RDP 密码和明文命令不会上传。

客户端除 HTTPS 外还会固定验证自托管云的 Ed25519 身份公钥。首次启动服务前必须生成服务器私钥；客户端只填写公钥。完整协议和官方双服务部署见 [OFFICIAL_CLOUD_DEPLOYMENT.md](OFFICIAL_CLOUD_DEPLOYMENT.md)。

生产数据库固定推荐 **MySQL 8.4.10 LTS**。部署文件钉住完整镜像版本 `mysql:8.4.10`，避免 `latest` 或浮动标签在无人确认时跨版本升级。HeartLink 一键安装与下述 Compose 部署默认使用官方仓库集中构建的 `amd64`/`arm64` 预编译镜像，并锁定不可变摘要；用户服务器不需要安装 Rust，也不会执行 `cargo build`。

一键安装器默认先从 GHCR 拉取 HeartLink 镜像；如果 GHCR 分层下载失败，会自动切换到南京大学公共镜像站并继续拉取同一个固定摘要。手工 Compose 部署遇到相同网络问题时，可把 `HEARTLINK_SERVER_IMAGE` 的仓库前缀替换为 `ghcr.nju.edu.cn/hearthrobxd/heartlink-self-hosted`，但必须保留发行说明中的完整 `@sha256:...` 摘要。

## 一、统一 IP 端点与可选反向代理

HeartLink 云端不区分局域网和公网安装模式，也不要求域名。业务 API 固定使用发布 IP 的 `8787` 端口，管理面板固定使用发布 IP 的 `8789` 端口。管理应用只接受回环、局域网/私网来源或同机反向代理；公网来源直接访问 `8789` 会按安全策略返回 `403`。需要公网管理或 HTTPS 时，由用户选择 IP 或域名作为外部地址，并自行配置证书、WAF 和反向代理。下面的雷池拓扑只是一种可选部署方式。

```text
HeartLink 客户端
        │ HTTPS 443
        ▼
前置服务器 / 雷池 SafeLine WAF
        │ HTTP 8787（只允许 WAF 源 IP）
        ▼
真实业务机 / 1Panel
  ├─ heartlink-sync:8787
  └─ mysql:3306（仅 Docker 网络，不发布到公网）
```

雷池只代理 HeartLink 的 HTTP 服务端口，**不代理 MySQL 3306**。数据库与同步容器加入同一个 Docker 网络，通过 MySQL 容器名连接。业务机防火墙只允许前置 WAF 的源 IP 访问 `8787`；公网只暴露 WAF 的 `80/443`。

雷池站点的上游填写 `http://<业务机内网IP>:8787`，在 WAF 终止 TLS。建议：

- 为登录、注册和 `/v1/auth/recovery/*` 找回接口启用按源 IP 限速；验证码申请和校验应使用比普通 API 更严格的限额；
- 请求体上限至少设为 `2 MiB`；
- 保留 `Authorization`、`Content-Type`、`X-HeartSSH-*` 应用握手头、`X-HeartLink-Device-Id` 与 `X-HeartLink-Device-Control`；不要把设备控制头写入 WAF 访问日志；
- 健康检查使用 `GET /health`；
- 不缓存 `/v1/*`，不启用会改写 JSON 正文的功能。

客户端“自托管云”可以填写可信私网的 `http://IP:8787`，也可以填写用户自管网关提供的 `https://IP`、`https://IP:PORT` 或域名地址。`https://IP` 的证书必须包含对应 IP 的 Subject Alternative Name，并受客户端系统信任。不要填写 MySQL 地址。

## 二、1Panel 已有 MySQL 容器：推荐安装方式

### 1. 准备 MySQL 8.4.10 LTS

在 1Panel 的应用商店安装 MySQL 8.4，并确认实际镜像版本为 `mysql:8.4.10`。如果已经使用兼容的 MySQL 8.4 实例，可以直接复用，但应创建独立数据库和独立账户：

```sql
CREATE DATABASE heartlink CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
CREATE USER 'heartlink'@'%' IDENTIFIED BY '替换为独立的高强度随机密码';
GRANT ALL PRIVILEGES ON heartlink.* TO 'heartlink'@'%';
```

`'%'` 只表示允许来自容器网络的主机；MySQL 容器仍不得把 `3306` 发布到公网。若 1Panel 必须发布端口，只绑定业务机回环或内网地址，并用防火墙拒绝外部来源。

### 2. 确认容器名和共享网络

在业务机上查看 MySQL 容器名及网络：

```bash
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Ports}}'
docker inspect <MySQL容器名> --format '{{json .NetworkSettings.Networks}}'
```

记录 MySQL 容器名，例如 `1Panel-mysql-xxxx`，以及它所在的 Docker 网络名。HeartLink 同步容器会加入这个外部网络。

### 3. 配置并启动 HeartLink

在项目根目录创建仅管理员可读的环境文件。示例已经包含锁定的官方预编译镜像：

```bash
cp infra/docker/.env.example infra/docker/.env
chmod 600 infra/docker/.env
```

编辑 `infra/docker/.env`：

```dotenv
HEARTLINK_DATABASE_HOST=1Panel-mysql-xxxx
HEARTLINK_DATABASE_PORT=3306
HEARTLINK_DATABASE_NAME=heartlink
HEARTLINK_DATABASE_USER=heartlink
HEARTLINK_DATABASE_PASSWORD=替换为上一步的独立随机密码
HEARTLINK_DOCKER_NETWORK=1panel-network-name
HEARTLINK_SERVER_IMAGE=ghcr.io/hearthrobxd/heartlink-self-hosted:1.4.0@sha256:ca11b030a629c4e7eaeb38b9c39959aba4e8de576b4bb06dc4b2d5a9e7aaa3d9
HEARTLINK_HANDSHAKE_KEY_PATH=./secrets/cloud-handshake.key
HEARTLINK_HANDSHAKE_KEY_ID=self-hosted-cloud-v1

# 选择需要发布业务 API 和管理面板的 IPv4 地址；0.0.0.0 表示所有 IPv4 接口
HEARTLINK_PUBLISH_IP=10.0.0.20
HEARTLINK_PANEL_PUBLISH_IP=10.0.0.20
HEARTLINK_REGISTRATION_ENABLED=true

# 账户/解锁密码找回。至少配置一种发送通道，并使用不少于 32 个字符的独立 pepper。
HEARTLINK_RECOVERY_EMAIL_WEBHOOK=https://notify.example.com/heartlink/email
HEARTLINK_RECOVERY_SMS_WEBHOOK=https://notify.example.com/heartlink/sms
HEARTLINK_RECOVERY_WEBHOOK_TOKEN=替换为验证码服务的Bearer令牌
HEARTLINK_RECOVERY_PEPPER=替换为至少32个字符的独立随机值
TZ=Asia/Shanghai
```

拉取预编译镜像并生成不可提交到 Git 的握手身份密钥：

```bash
server_image="$(sed -n 's/^HEARTLINK_SERVER_IMAGE=//p' infra/docker/.env)"
test -n "$server_image"
docker pull "$server_image"
mkdir -p infra/docker/secrets
docker run --rm --user 0:0 \
  -v "$PWD/infra/docker/secrets:/keys" \
  --entrypoint heartlink-server "$server_image" \
  --generate-handshake-key /keys/cloud-handshake.key
chmod 400 infra/docker/secrets/cloud-handshake.key
```

命令输出的是客户端需要填写的公钥；`cloud-handshake.key` 是服务器私钥，不得放进源码、镜像或客户端。

启动服务：

```bash
docker compose --env-file infra/docker/.env \
  -f infra/docker/compose.1panel.yaml pull sync
docker compose --env-file infra/docker/.env \
  -f infra/docker/compose.1panel.yaml up -d
docker compose --env-file infra/docker/.env \
  -f infra/docker/compose.1panel.yaml ps
curl --fail http://10.0.0.20:8787/health
```

健康检查应返回：

```json
{"status":"ok","protocol_version":1}
```

如果同步容器提示数据库连接失败，先在共享网络内验证容器名、端口和账户，不要通过开放公网 `3306` 绕过网络配置。

### 4. 可选：配置雷池和防火墙

1. 雷池新增站点，公网域名指向前置服务器。
2. 上游地址设为 `http://10.0.0.20:8787`，替换成真实业务机内网 IP。
3. 在业务机安全组/防火墙中，仅允许前置 WAF 的固定源 IP 访问 TCP `8787`。
4. 不向公网开放 `8787` 或 `3306`。
5. 用公网域名验证：`curl --fail https://sync.example.com/health`。

如果 WAF 与业务机之间跨公网，至少使用点对点 VPN/WireGuard 或 WAF 到业务机的双向 TLS 隧道；不要让明文 HTTP 经过不可信公网。

## 三、不使用 1Panel：自带 MySQL 的 Compose

此方式会同时启动 `heartlink-sync` 和私有网络内的 `mysql:8.4.10`：

Compose 使用两个网络：MySQL 只加入 `internal: true` 的数据库网络；HeartLink 同时加入该数据库网络和普通边缘网络。端口 `8787`/`8789` 从边缘网络发布，`3306` 仍不发布。不要把 HeartLink 也限制为只接入内部网络，否则 Docker 29 等版本可能保留期望的 `PortBindings`，却不创建实际宿主机监听。

```bash
cp infra/docker/.env.example infra/docker/.env
chmod 600 infra/docker/.env
```

至少替换以下两个密码，并保持二者不同：

```dotenv
HEARTLINK_DATABASE_PASSWORD=应用账户的高强度随机密码
HEARTLINK_DATABASE_ROOT_PASSWORD=另一个高强度随机密码
```

启动并检查：

```bash
docker compose --env-file infra/docker/.env \
  -f infra/docker/compose.yaml pull sync mysql
docker compose --env-file infra/docker/.env \
  -f infra/docker/compose.yaml up -d
curl --fail http://127.0.0.1:8787/health
```

默认将 `8787` 和 `8789` 绑定到 `0.0.0.0`，因此可通过服务器 IP 访问。若只允许某块网卡、回环地址或反向代理访问，请分别设置 `HEARTLINK_PUBLISH_IP` 和 `HEARTLINK_PANEL_PUBLISH_IP`，并使用防火墙限制来源。域名和 TLS 不由 Compose 管理。

首次创建自己的账户后，建议关闭开放注册：

```dotenv
HEARTLINK_REGISTRATION_ENABLED=false
```

然后再次执行对应的 `docker compose ... up -d`。已有账户仍可登录，新账户注册会返回拒绝。

## 四、可选：从源码安装 systemd 服务

此高级路径明确选择在本机编译，不属于一键安装流程。仅在需要自行修改源码或不使用 Docker 时采用；普通部署请使用前述预编译镜像。它适用于 amd64/arm64 且带 systemd 的常见 Linux 发行版，需要 Rust 1.85 或更高、C 编译工具、Git、CA 证书，以及一个已准备好的 MySQL 8.4 数据库。

```bash
git clone <你的 HeartLink 仓库地址> /tmp/heartlink-src
cd /tmp/heartlink-src
cargo build --locked --release -p heartlink-server

sudo useradd --system --home /var/lib/heartlink --create-home \
  --shell /usr/sbin/nologin heartlink
sudo install -d -o heartlink -g heartlink -m 0700 \
  /var/lib/heartlink /opt/heartlink/bin /etc/heartlink
sudo install -o root -g root -m 0755 \
  target/release/heartlink-server /opt/heartlink/bin/heartlink-server
sudo install -o root -g root -m 0644 \
  infra/systemd/heartlink-sync.service /etc/systemd/system/heartlink-sync.service
sudo install -o root -g heartlink -m 0640 \
  infra/systemd/server.env.example /etc/heartlink/server.env
sudo /opt/heartlink/bin/heartlink-server \
  --generate-handshake-key /etc/heartlink/cloud-handshake.key
sudo chown root:heartlink /etc/heartlink/cloud-handshake.key
sudo chmod 0640 /etc/heartlink/cloud-handshake.key
```

保存密钥生成命令输出的身份公钥供客户端固定验证。编辑 `/etc/heartlink/server.env` 中的 MySQL 地址、数据库、用户和密码，再启动：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now heartlink-sync
sudo systemctl status heartlink-sync
curl --fail http://127.0.0.1:8787/health
```

该源码编译路径升级时先备份 MySQL，再重新构建和替换二进制；使用一键安装器或 Compose 预编译镜像时无需执行本步骤。数据库迁移会在服务启动时自动向前执行，包括账户手机号、验证码挑战和一次性找回令牌表。

## 五、服务配置项

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `HEARTLINK_DATABASE_URL` | 无 | 可选完整 URL，例如 `mysql://heartlink:密码@mysql:3306/heartlink`。设置后优先于下列拆分配置。 |
| `HEARTLINK_DATABASE_HOST` | `127.0.0.1` | MySQL 主机；容器部署应使用 MySQL 容器名。 |
| `HEARTLINK_DATABASE_PORT` | `3306` | MySQL 端口。 |
| `HEARTLINK_DATABASE_NAME` | `heartlink` | 独立数据库名。 |
| `HEARTLINK_DATABASE_USER` | `heartlink` | 独立应用账户。 |
| `HEARTLINK_DATABASE_PASSWORD` | 无，必填 | 应用账户密码。拆分变量会安全编码特殊字符。 |
| `HEARTLINK_BIND` | `127.0.0.1:8787` | HTTP 监听地址；容器内使用 `0.0.0.0:8787`。 |
| `HEARTLINK_PUBLISH_IP` | `0.0.0.0` | Compose 发布业务端口 `8787` 的 IPv4 地址。 |
| `HEARTLINK_PANEL_PUBLISH_IP` | `0.0.0.0` | Compose 发布管理面板端口 `8789` 的 IPv4 地址。 |
| `HEARTLINK_SERVICE_ROLE` | `cloud` | 自托管同步固定使用 `cloud`；官方更新进程使用 `update`。 |
| `HEARTLINK_HANDSHAKE_KEY_FILE` | 无，必填 | 服务器独占的 Base64URL Ed25519 私钥种子文件。 |
| `HEARTLINK_HANDSHAKE_KEY_ID` | `self-hosted-v1` | 公钥轮换标识；修改私钥时必须同步发布新的客户端信任配置。 |
| `HEARTLINK_REGISTRATION_ENABLED` | `true` | `false` 或 `0` 会关闭新账户注册。 |
| `HEARTLINK_RECOVERY_EMAIL_WEBHOOK` | 无 | 邮箱验证码发送服务的 HTTPS webhook；不配置则不能通过邮箱找回。 |
| `HEARTLINK_RECOVERY_SMS_WEBHOOK` | 无 | 短信验证码发送服务的 HTTPS webhook；不配置则不能通过手机找回。 |
| `HEARTLINK_RECOVERY_WEBHOOK_TOKEN` | 无 | 可选。服务端请求验证码 webhook 时使用的 bearer token。 |
| `HEARTLINK_RECOVERY_PEPPER` | 无 | 启用任一找回通道时必填，至少 32 个字符，用于服务端验证码摘要；不要与数据库密码共用。 |
| `RUST_LOG` | `info` | Rust 日志过滤器，不记录 bearer token 或密文正文。 |

旧版 `ASTER_DATABASE_URL` 和 `ASTER_BIND` 仍可读取。SQLite URL 仅用于兼容开发和既有测试；新生产部署使用 MySQL 8.4，不要把 SQLite 文件直接复制成 MySQL 数据。

## 六、客户端注册、登录与同步

1. 打开 HeartLink 的“数据与同步”，选择“自托管云”。
2. 填入基于 IP 或域名的云端地址，以及部署时生成命令输出的 Ed25519 身份公钥。可用形式包括可信私网 `http://IP:8787`，以及证书有效的 `https://IP`、`https://IP:PORT` 或域名地址。
3. 首次使用选择“注册”；填写邮箱、国际格式手机号码（例如 `+8613800138000`）以及至少 12 个字符的账户密码。之后使用邮箱和密码登录。
4. 首次点击云端同步时设置独立的“云端同步密码”，至少 16 个字符。它只在客户端用于 Argon2id 派生和 XChaCha20-Poly1305 加密，不会上传；首次同步成功后由当前 Windows 用户的 DPAPI 保险库保存，后续变更会静默同步，不再反复要求输入。
5. 点击“立即同步”。首次本地与云端同时有数据时必须明确选择保留本地或使用云端，不会静默覆盖。
6. “刷新设备”查看已登录设备；撤销设备必须再次输入云端账号密码。“退出云端”只结束当前账号会话，不等同于撤销设备。

客户端同步的对象包括服务器资料、SSH 隧道、终端设置、代理、分组、标签和加密凭据快照。云端只保存不可读密文及修订元数据。

新版客户端登记设备时会额外生成一个独立高熵设备控制令牌；服务端只保存其摘要。撤销设备后，服务端立即使该设备的账号登录令牌失效，并持久保存“清空本机 HeartLink 数据并退出账号”指令。在线设备会立即领取，离线设备下次启动或恢复网络后领取；客户端本地执行完成前，同一指令会持续返回，避免网络响应丢失。后台只记录设备 ID、指令 ID 和签发/下发/确认时间，不记录设备控制令牌、密文正文或本地数据。旧客户端没有登记设备控制令牌时，服务端仍会立即撤销其云端访问，但无法远程确认该旧客户端已经清空本机数据；后台会明确标记为“旧客户端未启用远程清空”。

HTTP 仅允许在用户显式启用后连接 `localhost` 或 RFC 1918 私网 IP。HTTPS 可以使用 IP 或域名，但证书必须与输入地址匹配并受系统信任；客户端不会跳过证书校验。公网明文 HTTP 仍会被拒绝。

### 验证码发送服务

管理后台可直接配置 SMTP 邮件和阿里云短信，也保留通用 HTTPS webhook。没有配置对应通道时，客户端会明确提示“云端尚未配置邮件或短信验证码服务”。

#### 阿里云短信（中国大陆）

1. 在阿里云短信服务中完成资质、签名和验证码模板审核。模板变量必须包含 `code`，例如 `您的验证码为${code}`。
2. 建议创建只允许调用短信发送接口的 RAM 用户，不要填写主账号 AccessKey。
3. 在 HeartLink 云端后台“服务设置”中选择“阿里云短信（中国大陆）”，填写 AccessKey ID、AccessKey Secret、审核通过的签名名称和 `SMS_` 开头的模板代码，然后启用短信验证码。
4. AccessKey 会使用云端设置密钥加密保存；后台读取时只返回“已配置”，不会回显原值。

服务端固定请求阿里云中国站 `dysmsapi.aliyuncs.com` 的 `SendSms` 接口，使用当前推荐的 `Dysmsapi` `2017-05-25`（这是 API 版本标识，不是旧接口）和 `ACS3-HMAC-SHA256` 签名。该适配只接受注册为 `+86` 的中国大陆手机号；港澳台或国际号码应选择相应供应商的 webhook。WAF 应允许云端服务器按域名主动访问该 HTTPS 端点，不要固定其动态 IP，同时继续对客户端的验证码申请、校验和密码重置接口限速。参数与签名格式应以[阿里云 SendSms 官方文档](https://help.aliyun.com/zh/sms/developer-reference/api-dysmsapi-2017-05-25-sendsms)为准。

#### 通用 webhook

启用 webhook 时，HeartLink 会向相应地址发送一个 `POST` JSON 请求：

```json
{
  "channel": "email",
  "destination": "user@example.com",
  "code": "123456",
  "purpose": "account_password",
  "expires_in_seconds": 600
}
```

- `channel` 为 `email` 或 `phone`；
- `purpose` 为 `account_password`（重置云端账户密码）或 `unlock_password`（授权客户端重置 HeartLink 解锁密码）；
- 如果配置了 `HEARTLINK_RECOVERY_WEBHOOK_TOKEN`，请求包含 `Authorization: Bearer <token>`；
- webhook 必须以 HTTP `2xx` 响应表示已经接收，其他状态会令客户端得到“验证码发送失败”；
- 生产环境必须使用 HTTPS，发送服务不得把验证码、令牌或完整手机号写入普通访问日志。

验证码 10 分钟有效，同一账户、用途和通道 60 秒内不会重复发送，最多允许 5 次校验。验证成功后得到的短时令牌同样在 10 分钟内有效、绑定具体用途且只能使用一次。重置账户密码会撤销该账户全部现有登录会话；解锁密码找回只授权已验证的客户端替换本机密码校验值，服务端仍不会收到解锁密码明文，后续由端到端加密的安全设置同步传播。

没有配置任何验证码 webhook 时，找回接口会明确返回不可用，不会把验证码回传给客户端或写到服务日志。WAF 仍必须针对验证码申请、验证码尝试和密码重置接口做源 IP 限速与异常告警。

## 七、自托管与官方在线更新的边界

选择“自托管云”只改变账号、设备和端到端密文同步的云端地址，不改变软件更新来源。HeartLink 客户端仍固定从官方 `https://update.heartlink.idcnyun.com` 获取签名版本清单和公开安装包；自托管同步服务不提供 `update` 角色、不持有官方更新私钥，也不能给客户端替换官方安装包。

更新请求与同步请求相互独立：客户端必须先完成官方更新端点的 X25519/Ed25519 应用握手，再校验 Ed25519 清单签名、包大小和 SHA-256，之后才接受安装包。自托管服务器或 WAF 无需转发 `8788`。受限网络应放行客户端到官方更新域名的 HTTPS 访问；完全离线环境可以关闭在线检查并由管理员离线分发经过签名和哈希核对的官方安装器，不能把自建同步地址伪装成官方更新端点。

## 八、备份、恢复与升级

容器部署建议每天做 MySQL 逻辑备份：

```bash
docker exec <MySQL容器名> sh -c \
  'exec mysqldump -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" \
  --single-transaction --routines --triggers \
  --set-gtid-purged=OFF "$MYSQL_DATABASE"' \
  > heartlink-$(date +%F).sql
chmod 600 heartlink-*.sql
```

该命令适用于项目自带的 MySQL 容器；复用 1Panel MySQL 时优先使用 1Panel 的数据库备份任务，或换成该实例实际的账户环境变量。恢复前停止 HeartLink 同步容器，创建空数据库后导入备份，再启动同步容器并检查 `/health`。不要在 MySQL 正在写入时直接复制 `/var/lib/mysql`；物理快照必须使用 1Panel/MySQL 支持的一致性备份流程。

升级步骤：

1. 阅读新版本交付说明并备份数据库；
2. 将 `mysql:8.4.10` 升级到新补丁版本前单独验证，不自动追随浮动标签；
3. 将环境文件中的 `HEARTLINK_SERVER_IMAGE` 更新到发行说明指定的新固定摘要，并拉取该预编译镜像；
4. 启动后检查容器日志、`/health`、注册/登录和一次双向同步；
5. 保留上一版镜像和数据库备份，直到验证完成。

正式承载高价值密钥前，仍应完成独立安全审计、恢复演练、WAF/TLS 检查和异常认证告警。
