# 构建

## 环境

当前脚本用于 Windows，使用 Python 3.11 和 Zig 0.15.2。将 Zig 放到 `toolchains/zig-x86_64-windows-0.15.2/`；三个上游仓库由 submodule 固定版本。

```powershell
git clone --recurse-submodules https://github.com/Timeline692/a7RV-Noctis-firmware.git
cd a7RV-Noctis-firmware
python -m pip install -r requirements.txt
python -c "from pathlib import Path; Path('analysis').mkdir(exist_ok=True)"
```

## 输入

原厂 A7R V 4.00 放在 `inputs/BODYDATA.DAT`，其 SHA-256 必须为：

```text
51e1176a255a9a4b4782dfbcfa6c5f332b71173bdfe9ed2bcf4fca6bcbc6c2e2
```

`python tools/probe_firmware.py inputs/BODYDATA.DAT --decode` 核对包身份并输出 `analysis/firmware-decrypted.fdat`。同一原包还需提取：

- `analysis/targets/nflasha15/lib/appFw.so`
- `analysis/targets/nflasha8/cpapp-b.bin`
- `analysis/targets/menu/` 下的原语言资源
- `sound-port/container/fs/nflasha15.original.img`
- `sound-port/container/fs/nflasha8.original.img`

这些输入、编译输出与临时记录均由 `.gitignore` 排除。菜单源代码、重定位表和资源清单属于组件生成的必要输入，保存在 `sound-port/menu/`。

## 构建入口

脚本分阶段执行，尚未提供一键构建。AP、CP 与资源需要来自同一批源码。

1. `sound-port/tools/build_ap.py` 编译 AP。菜单数据由 `generate_menu_metadata.py` 生成；`check_menu_cache_contract_once.py` 将 AP 和菜单装入原始 ELF，并核对安装合同。
2. `sound-port/cp/build.py` 编译默认 CP；`check_cp_component_once.py` 或 `patch_cp.py` 生成组件。第一版 DAT 显式使用 `--profile reference-codec-experimental`，之前需要生成 `all-busy-mapped` 默认组件。编译和安装检查仍保留，原生绑定、RPC 约束与参考格式约束位于 `sound-port/config/`。
3. `sound-port/tools/build_menu_resources.py` 生成 68 份 UXC。`sound-port/container/fs/rebuild_fs.py` 组装 AP EXT2 与 CP FAT12；e2fs 工具通过同目录的 `acquire_e2fs_tools.py` 获取。
4. 使用自己的 RSA2048 密钥对封包，选择尚不存在的输出目录：

```powershell
python sound-port/container/build_dat.py --original inputs/BODYDATA.DAT --private-key inputs/private.pem --public-key inputs/public.pem --output output/custom-dat
```

发布公钥在 `sound-port/container/keys/RV-SoundMenu-public.pem`，用于验证已有发布；私钥不随项目分发。不同签名密钥会产生不同的 DAT 哈希。包内版本号保持 4.01。

`sound-port/container/verify/verify_rv_dat.py --help` 提供独立回读参数，核对容器、签名、清单和实际组件。构建产生的清单与检查输出仅保存在本地，不提交到仓库。
