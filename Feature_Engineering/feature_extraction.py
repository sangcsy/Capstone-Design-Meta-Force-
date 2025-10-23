#!/usr/bin/env python
"""Feature subset extraction aligned with published encrypted traffic studies."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict, List

try:
    import pandas as pd
except ImportError as exc:
    raise ImportError("pandas is required to run this script.") from exc


DatasetSpec = Dict[str, object]
StudySpec = Dict[str, object]


DATASETS: Dict[str, DatasetSpec] = {
    "cic-ids": {
        "path": Path("Data/CIC-IDS/CIC-IDS-2017-train_features.csv"),
        "studies": {
            "anderson2016": {
                "reference": "Anderson & McGrew (2016) – encrypted malware detection with flow metadata.",
                "columns": [
                    "Flow Duration",
                    "Total Fwd Packets",
                    "Total Backward Packets",
                    "Total Length of Fwd Packets",
                    "Total Length of Bwd Packets",
                    "Fwd Packet Length Mean",
                    "Fwd Packet Length Std",
                    "Bwd Packet Length Mean",
                    "Bwd Packet Length Std",
                    "Flow Bytes/s",
                    "Flow Packets/s",
                    "Flow IAT Mean",
                    "Flow IAT Std",
                    "Flow IAT Max",
                    "Flow IAT Min",
                    "Fwd IAT Mean",
                    "Fwd IAT Std",
                    "Bwd IAT Mean",
                    "Bwd IAT Std",
                    "Min Packet Length",
                    "Max Packet Length",
                    "Packet Length Mean",
                    "Packet Length Std",
                    "Packet Length Variance",
                    "FIN Flag Count",
                    "SYN Flag Count",
                    "RST Flag Count",
                    "PSH Flag Count",
                    "ACK Flag Count",
                    "URG Flag Count",
                    "Down/Up Ratio",
                    "Average Packet Size",
                ],
            },
            "draper_gil2016": {
                "reference": "Draper-Gil et al. (2016) – CICFlowMeter VPN/non-VPN characterization.",
                "columns": [
                    "Flow Duration",
                    "Total Fwd Packets",
                    "Total Backward Packets",
                    "Total Length of Fwd Packets",
                    "Total Length of Bwd Packets",
                    "Fwd Packet Length Max",
                    "Fwd Packet Length Min",
                    "Fwd Packet Length Mean",
                    "Fwd Packet Length Std",
                    "Bwd Packet Length Max",
                    "Bwd Packet Length Min",
                    "Bwd Packet Length Mean",
                    "Bwd Packet Length Std",
                    "Flow IAT Mean",
                    "Flow IAT Std",
                    "Flow IAT Max",
                    "Flow IAT Min",
                    "Fwd IAT Mean",
                    "Fwd IAT Std",
                    "Bwd IAT Mean",
                    "Bwd IAT Std",
                    "Fwd Packets/s",
                    "Bwd Packets/s",
                    "Min Packet Length",
                    "Max Packet Length",
                    "Packet Length Mean",
                    "Packet Length Std",
                    "Active Mean",
                    "Active Std",
                    "Active Max",
                    "Active Min",
                    "Idle Mean",
                    "Idle Std",
                    "Idle Max",
                    "Idle Min",
                ],
            },
            "lotfollahi2017": {
                "reference": "Lotfollahi et al. (2017) – autoencoder-based encrypted traffic classification.",
                "columns": [
                    "Flow Duration",
                    "Total Fwd Packets",
                    "Total Backward Packets",
                    "Flow Bytes/s",
                    "Flow Packets/s",
                    "Fwd IAT Mean",
                    "Fwd IAT Std",
                    "Bwd IAT Mean",
                    "Bwd IAT Std",
                    "Avg Fwd Segment Size",
                    "Avg Bwd Segment Size",
                    "Init_Win_bytes_forward",
                    "Init_Win_bytes_backward",
                    "act_data_pkt_fwd",
                    "min_seg_size_forward",
                    "Active Mean",
                    "Idle Mean",
                    "Active Max",
                    "Idle Max",
                ],
            },
        },
    },
    "unsw-nb15": {
        "path": Path("Data/UNSW-NB15/UNSW-NB15_trainset.csv"),
        "studies": {
            "moustafa2015_full": {
                "reference": "Moustafa & Slay (2015) – UNSW-NB15 49 feature baseline.",
                "columns": [
                    "dur",
                    "spkts",
                    "dpkts",
                    "sbytes",
                    "dbytes",
                    "rate",
                    "sttl",
                    "dttl",
                    "sload",
                    "dload",
                    "sloss",
                    "dloss",
                    "sinpkt",
                    "dinpkt",
                    "sjit",
                    "djit",
                    "swin",
                    "stcpb",
                    "dtcpb",
                    "dwin",
                    "tcprtt",
                    "synack",
                    "ackdat",
                    "smean",
                    "dmean",
                    "trans_depth",
                    "response_body_len",
                    "ct_srv_src",
                    "ct_state_ttl",
                    "ct_dst_ltm",
                    "ct_src_dport_ltm",
                    "ct_dst_sport_ltm",
                    "ct_dst_src_ltm",
                    "is_ftp_login",
                    "ct_ftp_cmd",
                    "ct_flw_http_mthd",
                    "ct_src_ltm",
                    "ct_srv_dst",
                    "is_sm_ips_ports",
                ],
            },
            "zhou2020_top12": {
                "reference": "Zhou et al. (2020) – top-12 UNSW-NB15 flow/meta features.",
                "columns": [
                    "dur",
                    "spkts",
                    "dpkts",
                    "sbytes",
                    "dbytes",
                    "rate",
                    "sttl",
                    "dttl",
                    "sload",
                    "dload",
                    "ct_state_ttl",
                    "ct_srv_dst",
                ],
            },
        },
    },
    "vpn-nonvpn": {
        "path": Path("Data/VPN-nonVPN/VPN-nonVPN_train_features.csv"),
        "studies": {
            "draper_gil2016": {
                "reference": "Draper-Gil et al. (2016) – VPN vs non-VPN burstiness features.",
                "columns": [
                    "duration",
                    "flowbytespersecond",
                    "flowpktspersecond",
                    "max_active",
                    "mean_active",
                    "min_active",
                    "std_active",
                    "max_idle",
                    "mean_idle",
                    "min_idle",
                    "std_idle",
                    "max_flowiat",
                    "mean_flowiat",
                    "min_flowiat",
                    "std_flowiat",
                    "time_window_s",
                    "total_fiat",
                    "total_biat",
                ],
            },
            "shen2018_lightweight": {
                "reference": "Shen et al. (2018) – lightweight encrypted traffic identification.",
                "columns": [
                    "duration",
                    "flowbytespersecond",
                    "flowpktspersecond",
                    "mean_fiat",
                    "mean_biat",
                    "mean_active",
                    "mean_idle",
                    "std_active",
                    "std_idle",
                    "max_active",
                    "max_idle",
                    "time_window_s",
                ],
            },
        },
    },
}


def validate_columns(df_columns: List[str], expected: List[str]) -> None:
    missing = [col for col in expected if col not in df_columns]
    if missing:
        raise KeyError("Missing columns: {}".format(", ".join(missing)))


def load_dataframe(dataset_key: str, root_dir: Path) -> pd.DataFrame:
    dataset = DATASETS.get(dataset_key)
    if not dataset:
        raise KeyError("Unknown dataset {}".format(dataset_key))
    csv_path = (root_dir / dataset["path"]).resolve()
    if not csv_path.exists():
        raise FileNotFoundError("Cannot find {}".format(csv_path))
    return pd.read_csv(csv_path)


def extract_feature_set(
    dataset_key: str,
    study_key: str,
    root_dir: Path = Path("."),
) -> pd.DataFrame:
    dataset = DATASETS.get(dataset_key)
    if not dataset:
        raise KeyError("Unknown dataset {}".format(dataset_key))
    study: StudySpec = dataset["studies"].get(study_key)  # type: ignore[assignment]
    if not study:
        raise KeyError(
            "Unknown study {} for dataset {}".format(study_key, dataset_key)
        )
    df = load_dataframe(dataset_key, root_dir)
    columns = study["columns"]  # type: ignore[index]
    validate_columns(df.columns.tolist(), columns)
    return df.loc[:, columns].copy()


def list_options() -> str:
    lines: List[str] = []
    for dataset_key, dataset in DATASETS.items():
        lines.append(dataset_key)
        for study_key, spec in dataset["studies"].items():
            lines.append("  - {}: {}".format(study_key, spec["reference"]))
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract feature subsets aligned with published research."
    )
    parser.add_argument(
        "--dataset",
        choices=sorted(DATASETS.keys()),
        help="Dataset key to use.",
    )
    parser.add_argument(
        "--study",
        help="Study key defining the feature subset.",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path("."),
        help="Project root (defaults to current directory).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional path to save the selected features as CSV.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Directory to save all study outputs when --all is set.",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Extract all study presets associated with the chosen dataset.",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available dataset/study combinations.",
    )
    args = parser.parse_args()
    if args.list:
        print(list_options())
        parser.exit()
    if not args.dataset:
        parser.error("--dataset is required.")
    if args.all and args.study:
        parser.error("--study cannot be combined with --all.")
    if args.all and args.output:
        parser.error("--output cannot be combined with --all; use --output-dir instead.")
    if not args.all and not args.study:
        parser.error("Provide --study for a single extraction or use --all.")
    return args


def main() -> None:
    args = parse_args()
    if args.all:
        dataset = DATASETS[args.dataset]
        target_dir = args.output_dir or Path("outputs")
        target_dir = (args.root / target_dir).resolve()
        target_dir.mkdir(parents=True, exist_ok=True)
        for study_key in dataset["studies"]:
            subset = extract_feature_set(args.dataset, study_key, args.root)
            output_path = target_dir / "{}_{}.csv".format(args.dataset, study_key)
            subset.to_csv(output_path, index=False)
            print(
                "Saved {} rows × {} columns to {}".format(
                    subset.shape[0], subset.shape[1], output_path
                )
            )
    else:
        subset = extract_feature_set(args.dataset, args.study, args.root)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            subset.to_csv(args.output, index=False)
            print(
                "Saved {} rows × {} columns to {}".format(
                    subset.shape[0], subset.shape[1], args.output.resolve()
                )
            )
        else:
            info = DATASETS[args.dataset]["studies"][args.study]["reference"]
            print(info)
            print(
                "Selected columns ({}): {}".format(
                    len(subset.columns), list(subset.columns)
                )
            )
            print(subset.head())


if __name__ == "__main__":
    main()
