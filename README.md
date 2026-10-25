# Noctis · Sony A7R V 自定义声音固件

基于 A7R V（ILCE-7RM5）原厂 4.00，研究在相机菜单内自定义电子快门声与合焦提示音。

- 从 SD 卡 `PRIVATE/SONY/PRO/SOUNDS/*.WAV` 导入音频。
- 快门与合焦独立开关、10 档音量、保存与启动恢复。
- AP、CP 和 68 份语言资源封装为完整 DAT。

## 第一版下载

[v0.1.0](https://github.com/Timeline692/a7RV-Noctis-firmware/releases/tag/v0.1.0) 附件提供完整 `BODYDATA.DAT`、SHA-256 和验签公钥。包内版本号为 **4.01**，是项目自定义编号，发布版本保持 **v0.1.0**。

本版已完成离线封包与校验，尚未实机验证。原厂 4.00 更新器不直接信任项目公钥，安装前仍需准备接收端；本包不改写 p1。无裁切 4K60 未包含在本版。

## 源码

`sound-port/` 包含 AP/CP 声音实现、菜单、构建和封包工具；`sound-port/config/` 保存构建必需的原生绑定与格式约束。环境和输入见[构建说明](docs/BUILD.md)。分析报告、设备备份、工具链和私钥不纳入仓库。

## 用途与责任

本项目仅供教育、学习与固件研究，按现状提供。使用者自行承担操作及其后果；作者不对用户行为，以及由此造成的设备变砖、数据丢失或其他损失负责。

## 致谢

参考 [sony-a7m4-custom-firmware](https://github.com/Erlla/sony-a7m4-custom-firmware)，使用 [sony-a7iv-feature-research](https://github.com/leogenot/sony-a7iv-feature-research) 与 [fwtool.py](https://github.com/DavidBuchanan314/fwtool.py)。固定提交和许可见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
