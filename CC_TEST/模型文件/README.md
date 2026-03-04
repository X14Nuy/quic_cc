# 模型阶段（XGBoost + SHAP）

本目录用于完成“提取特征 -> 建模评估 -> 解释分析”的闭环。

## 1. 文件说明

- `build_flow_dataset.py`
  - 将 `packets_udp.csv` 聚合为流级样本（flow-level features）。
- `train_xgboost_shap.py`
  - 训练 `XGBoost` 二分类模型，并导出 `SHAP` 全局解释。
- `dataset_manifest.example.json`
  - 数据源清单示例（每个 source 指定路径和标签）。
- `run_xgb_pipeline.sh`
  - 一键运行脚本（构建数据集 + 训练 + 解释）。
- `requirements.txt`
  - Python 依赖。

## 2. 为什么是 XGBoost + SHAP

结合近期加密流量检测文献，本项目目标是：
1) 用流级统计特征检测异常；
2) 在答辩中可解释“为什么判为异常”。

这对应 `XGBoost + SHAP`：
- XGBoost：对表格统计特征（长度/IAT/流持续时间）鲁棒、训练效率高。
- SHAP：可输出每个特征对判定结果的贡献方向和强度。

文献参考（建议答辩时引用）：
- Scientific Reports 2025: ET-SSL（加密流量异常检测，强调流级统计特征）
- arXiv 2025: Explainable encrypted malware traffic detection（XGBoost + SHAP）
- Applied Sciences 2026: XGBoost-based IDS with interpretability for IoT

## 3. 快速开始

```bash
python3 -m pip install -r CC_TEST/模型文件/requirements.txt
bash CC_TEST/模型文件/run_xgb_pipeline.sh
```

运行后输出目录：
- `CC_TEST/模型文件/out/run_<timestamp>/`

关键产物：
- `metrics.json`
- `model_xgboost.json`
- `feature_importance_gain.csv`
- `shap_mean_abs.csv`
- `shap_beeswarm.png`
- `shap_bar.png`
- `test_predictions.csv`

## 4. 标签设计建议

当前示例 manifest 仅作为流程验证。要做“隐蔽性定量证明”，需要：
- `label=0`：真实背景正常 QUIC 流量（尽量跨主机、跨时段、跨业务）
- `label=1`：本项目信道流量（不同参数、不同负载强度）

避免同一抓包重复进入 train/test，以免指标虚高。
