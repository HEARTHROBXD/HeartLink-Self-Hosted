# HeartLink Self-Hosted Cloud

HeartLink 自部署托管云用于账号、设备、找回、管理后台和端到端密文同步。服务端只保存不透明密文，不代理 SSH、SFTP 或 RDP 流量，也不会接收客户端主密码、Vault 密钥或服务器明文凭据。

此仓库只包含 AGPL 自部署云和 Apache-2.0 协议模型。闭源桌面客户端、官方云运营模块、软件更新签名与安装包下发模块均不在仓库和自部署镜像中。

## 一键安装

支持 Debian、Ubuntu、RHEL、Rocky Linux、AlmaLinux、CentOS、Fedora、openSUSE、SLES、Arch Linux 的 x86_64/arm64 主机。脚本会安装缺失的 Docker Engine 与 Compose 插件，并在服务器本机从源码构建仅含自部署特性的镜像。

局域网模式：

```bash
curl -fsSL https://raw.githubusercontent.com/HEARTHROBXD/HeartLink-Self-Hosted/main/install.sh | sudo bash
```

公网 HTTPS 模式（两个域名必须已解析到服务器，80/443 端口可用）：

```bash
curl -fsSL https://raw.githubusercontent.com/HEARTHROBXD/HeartLink-Self-Hosted/main/install.sh | \
  sudo bash -s -- install \
  --cloud-domain cloud.example.com \
  --panel-domain panel.example.com \
  --email admin@example.com
```

安装完成后，终端和 `/opt/heartlink-cloud/install-result.txt` 会给出：

- 客户端云端地址；
- 管理面板地址和随机访问密码；
- 云端 Ed25519 身份公钥。

结果文件和数据库密码文件仅允许 root 读取。未配置域名时，管理面板只绑定 `127.0.0.1:8789`，可通过安装结果中给出的 SSH 隧道访问；局域网 HTTP 端点不能用于公网。

## 运维

```bash
sudo /opt/heartlink-cloud/current/install.sh status
sudo /opt/heartlink-cloud/current/install.sh upgrade
sudo /opt/heartlink-cloud/current/install.sh uninstall
```

普通卸载保留数据库卷、身份私钥和配置。只有显式增加 `--purge-data` 才会永久删除这些数据。升级使用新的只增版本目录并原子切换 `current`，原身份私钥和数据库卷保持不变。

## 开发验证

```bash
cargo fmt --all -- --check
cargo clippy -p heartlink-server --no-default-features --features self-hosted --all-targets -- -D warnings
cargo test -p heartlink-server --no-default-features --features self-hosted
docker build -f apps/server/Dockerfile .
```

接口保持版本化 `/v1`，数据库迁移只前进。协议字段采用向后兼容的可选扩展；官方云的新安全协议会使用独立版本和信任策略，不改变自部署云现有身份公钥和密文同步兼容性。

## 许可与安全

自部署服务为 `AGPL-3.0-only`，共享协议模型为 `Apache-2.0`，文档为 `CC-BY-4.0`。生产部署前请阅读 `SECURITY.md` 和 `docs/SELF_HOSTING_LINUX.md`，备份 `/opt/heartlink-cloud/secrets` 与 Docker 数据卷，并将身份公钥通过可信渠道录入客户端。
