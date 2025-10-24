# Encrypted Traffic Feature Extraction Toolkit

## 프로젝트 구조

- `Data/`  
  - `CIC-IDS/` – `CIC-IDS-2017-train_features.csv`, `CIC-IDS-2017-train_labels.csv`  
  - `UNSW-NB15/` – `UNSW-NB15_trainset.csv`, `UNSW-NB15_trainlabel.csv`, `my_scaler.pkl`  
  - `VPN-nonVPN/` – `VPN-nonVPN_train_features.csv`, `VPN-nonVPN_trainlabel.csv`  
  - `scripts/feature_extraction.py` – 연구별 특징 추출 스크립트
- `공격매핑알파벳순.txt` – 라벨 ID와 공격명 매핑표
- `outputs/` – 추출된 결과 샘플을 저장하는 디렉터리(필요 시 자동 생성)

## 준비 사항

- Python 3.9 이상
- 패키지: `pandas`

의존성 설치:

```bash
python3 -m pip install pandas
```

## 사용법

### 가용 연구 목록 확인

```bash
python3 Data/scripts/feature_extraction.py --list
```

데이터셋 키(`cic-ids`, `unsw-nb15`, `vpn-nonvpn`)와 연구 키(예: `anderson2016`, `moustafa2015_full`)를 확인할 수 있습니다.

### 특징 서브셋 추출

```bash
python3 Data/scripts/feature_extraction.py \
  --dataset cic-ids \
  --study anderson2016 \
  --output outputs/cic_anderson.csv
```

- `--dataset`: 데이터셋 키  
- `--study`: 연구 키  
- `--output`: 결과 CSV 저장 경로(생략 시 표준출력으로 요약/미리보기)
- `--root`: 프로젝트 루트 경로(기본값 현재 디렉터리)

필요한 연구 조합마다 동일한 명령을 반복 실행하면 각기 다른 파일로 저장됩니다. 예를 들어 UNSW-NB15 상위 12개 특징을 추출하려면

```bash
python3 Data/scripts/feature_extraction.py \
  --dataset unsw-nb15 \
  --study zhou2020_top12 \
  --output outputs/unsw_top12.csv
```

### 데이터셋 전체 프리셋 일괄 추출

```bash
python3 Data/scripts/feature_extraction.py \
  --dataset cic-ids \
  --all \
  --output-dir outputs
```

`--all` 옵션을 지정하면 선택한 데이터셋에 연결된 모든 연구 키를 순회하며 `<dataset>_<study>.csv` 형식으로 결과를 저장합니다. `--output-dir`을 생략하면 기본값으로 `outputs/` 디렉터리가 사용됩니다.

### 출력 확인

명령이 성공하면 다음과 같은 메시지가 표시됩니다.

```
Saved 12345 rows × 32 columns to /absolute/path/outputs/cic_anderson.csv
```

저장된 CSV는 바로 모델 학습 파이프라인에 연결하거나, 추가 전처리/검증 단계를 위해 로드해 사용할 수 있습니다.


### 참고 연구 및 특징 선택

- **Anderson & McGrew (2016)**  
  - 논문: Identifying Encrypted Malware Traffic Using Machine Learning (Workshop on Cyber Security Analytics, Intelligence and Automation)  
  - 데이터: Cisco 엔터프라이즈 테레메트리, CIC-IDS와 유사한 흐름 메타데이터  
  - 핵심 특징: 흐름 지속 시간, 전/후방 패킷 수, 바이트 합계, 패킷 길이 통계, 패킷 간 시간(IAT) 통계, TCP 플래그 카운터, `Flow Bytes/s`, `Flow Packets/s` 등으로 흐름의 양적 특성과 시간적 패턴, 세션 제어 플래그를 통합 분석  
  - 매핑: CIC-IDS 열을 선택해 `anderson2016` 프리셋 구성

- **Draper-Gil et al. (2016)**  
  - 논문: Characterization of Encrypted and VPN Traffic Using Time-Related Features (International Conference on Information Systems Security and Privacy)  
  - 데이터: ISCX VPN-nonVPN (CICFlowMeter 특징)  
  - 핵심 특징: 전/후방 패킷 길이 통계, IAT 통계, 활성(active)/휴면(idle) 기간의 평균·표준편차·최대·최소, 흐름 단위 속도 지표로 트래픽의 burstiness와 서비스 유형에 따른 시간적 변화를 파악  
  - 매핑 A: CIC-IDS 열을 선택해 `draper_gil2016` 프리셋 구성  
  - 매핑 B: VPN-nonVPN 열을 선택해 동일 이름의 프리셋 구성

- **Lotfollahi et al. (2017)**  
  - 논문: Deep Packet: A Novel Approach for Encrypted Traffic Classification Using Deep Learning (Elsevier)  
  - 데이터: ISCX Tor, VPN-nonVPN 등 암호화 트래픽  
  - 핵심 특징: 패킷 간 시간, 평균 세그먼트 크기, 초기 TCP 윈도 크기, `act_data_pkt_fwd`, `min_seg_size_forward`, 활성/휴면 통계 등을 오토인코더 입력으로 사용해 세션 단계의 미세한 패턴을 학습  
  - 매핑: CIC-IDS 열을 선택해 `lotfollahi2017` 프리셋 구성

- **Moustafa & Slay (2015)**  
  - 논문: UNSW-NB15: A Comprehensive Data Set for Network Intrusion Detection Systems (MILCOM)  
  - 데이터: UNSW-NB15  
  - 핵심 특징: `dur`, `spkts`, `sbytes`, `sttl`, `sinpkt`, `ct_state_ttl`, `is_sm_ips_ports` 등 49개 기반/콘텐츠/시간/추가 필드를 통해 트래픽 양·세션 상태·프로토콜 동작·포트 사용 패턴을 포괄  
  - 매핑: 제공된 UNSW-NB15 열을 활용해 `moustafa2015_full` 프리셋 구성

- **Zhou et al. (2020)**  
  - 논문: Building Flow-Based Fine-Grained Network Traffic Classification Systems Using Machine Learning (IEEE Access)  
  - 데이터: UNSW-NB15, CIC-IDS-2017 등  
  - 핵심 특징: 중요도 기반 상위 12개 흐름/메타 특징 (`dur`, `spkts`, `dpkts`, `sbytes`, `rate`, `sttl`, `dttl`, `sload`, `dload`, `ct_state_ttl`, `ct_srv_dst`, `dbytes`)으로 최소 특징 수로도 세션의 속도·부하·상태 변화를 포착  
  - 매핑: UNSW-NB15 열을 선택해 `zhou2020_top12` 프리셋 구성

- **Shen et al. (2018)**  
  - 논문: Towards Lightweight Attacks: Detecting VPN Encrypted Traffic via Machine Learning (IEEE International Conference on Information and Automation)  
  - 데이터: VPN-nonVPN  
  - 핵심 특징: 활성/휴면 기간 평균 및 표준편차, FIAT/BIAT 통계, 흐름 속도, 지속 시간으로 VPN 터널링이 만들어내는 burst-quiet 패턴을 경량 지표로 표현  
  - 매핑: VPN-nonVPN 열을 선택해 `shen2018_lightweight` 프리셋 구성