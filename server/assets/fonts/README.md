# Noto Sans CJK SC 字体

PDF 报告内嵌中文字体（SIL Open Font License 1.1，见 licenses/noto-fonts/LICENSE）。

- NotoSansCJKsc-Regular.otf：noto-cjk 仓库静态 OTF（CFF），存档备用。
  - 来源：https://github.com/notofonts/noto-cjk/raw/main/Sans/OTF/SimplifiedChinese/NotoSansCJKsc-Regular.otf
  - sha256：2c76254f6fc379fddfce0a7e84fb5385bb135d3e399294f6eeb6680d0365b74b
- NotoSansCJKsc-VF.ttf：noto-cjk 仓库可变 TTF（glyf），gofpdf 运行时实际内嵌字体。
  - 说明：gofpdf v2.17.3 不支持 CFF 格式 OTF，故 PDF 内嵌使用同仓库可变 TTF。
  - 来源：https://github.com/notofonts/noto-cjk/raw/main/Sans/Variable/TTF/NotoSansCJKsc-VF.ttf
  - sha256：990c807e79c25662a5a9ecf7f971baeb2bf2eab9a559e5ecf15cdfdb8561d21f
