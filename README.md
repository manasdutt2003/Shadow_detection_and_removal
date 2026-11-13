# Shadow Detection and Removal

A two-stage PyTorch system that finds shadows in an image and then removes
them, trained on the ISTD dataset.

1. **ShadowDESDNet** predicts a shadow mask. It uses a pretrained ResNeXt-50
   backbone followed by a dynamic attention block.
2. **ShadowRemoval** takes the image plus the predicted mask and produces a
   shadow-free image.

## Sample output

| Shadow detected | Shadow mask | Shadow removed |
| --- | --- | --- |
| ![shadow detected](https://github.com/user-attachments/assets/67ea42e3-06ae-4ae2-a8ac-e0a6940cc24a) | ![shadow mask](https://github.com/user-attachments/assets/65c287ca-3d4c-4a5f-81fb-9d2ffb9240e6) | ![shadow removed](https://github.com/user-attachments/assets/8a9fc392-7b33-414d-9ca8-6bac5c59e45d) |

## Installation

```bash
git clone https://github.com/manasdutt2003/Shadow_detection_and_removal.git
cd Shadow_detection_and_removal
python -m venv .venv
.venv\Scripts\activate          # macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
```

Python 3.9+ and PyTorch 2.x. A CUDA GPU is strongly recommended for training.

## Dataset

Download [ISTD](https://github.com/DeepInsight-PCALab/ST-CGAN) and arrange it as:

```
data/ISTD_dataset/
├── train/
│   ├── A/   shadow images
│   ├── B/   shadow masks
│   └── C/   shadow-free images
└── test/
    ├── A/
    ├── B/
    └── C/
```

## Usage

Train:

```bash
python main.py train --data_path data/ISTD_dataset --batch_size 8 --epochs 20 --lr 1e-4
```

A checkpoint is written every epoch and the best one by validation loss is
saved as `checkpoints/best_model.pth`. Follow progress with
`tensorboard --logdir logs`.

Evaluate (loss plus side-by-side result images in `results/`):

```bash
python main.py evaluate --model_path checkpoints/best_model.pth --data_path data/ISTD_dataset
```

Mask metrics (accuracy, precision, recall, F1):

```bash
python advanced_evaluate.py
```

Single image:

```bash
python predict.py --image_path path/to/image.jpg
```

Web demo:

```bash
streamlit run app.py
```

## About the committed checkpoint

`checkpoints/best_model.pth` in this repository was produced by
`create_dummy_weights.py`. It holds **random weights** so the app can start,
and its output is noise. Train the model as shown above to get real results;
the Streamlit app warns when it detects the placeholder.

## Reported results

Shadow-mask metrics previously reported for this project on the ISTD test set:

| Metric | Score |
| --- | --- |
| Accuracy | 0.95 |
| Precision | 0.91 |
| Recall | 0.89 |
| F1 score | 0.90 |

Re-run `python advanced_evaluate.py` with a trained checkpoint to reproduce them.

## Project structure

| Path | Purpose |
| --- | --- |
| `shadow_desdnet.py` | Shadow detection network |
| `shadow_removal.py` | Shadow removal network |
| `utils.py` | ISTD dataset and data loader |
| `train.py` | Training loop with mixed precision and gradient accumulation |
| `evaluate.py` | Loss evaluation and result visualisation |
| `advanced_evaluate.py` | Mask metrics |
| `predict.py` | Single-image inference |
| `main.py` | `train` / `evaluate` command-line entry point |
| `app.py` | Streamlit demo |
| `OUTPUTS/` | Sample outputs |
| `Research Paper.pdf`, `Presentation_DIP.pdf` | Project report and slides |
| `base_paper.pdf`, `reference_papers/` | Literature the project builds on |
| `generate_train_stats.py`, `update_train_stats.py` | Write simulated numbers to `data/train_stats.json` for a scheduled workflow. They are random, not measurements of this model. |

## Citation

```bibtex
@misc{dutt2023shadowremoval,
  author       = {Manas Dutt},
  title        = {Shadow Detection and Removal System},
  year         = {2023},
  howpublished = {\url{https://github.com/manasdutt2003/Shadow_detection_and_removal}}
}
```

## Acknowledgments

The ISTD dataset authors, the PyTorch community, and the authors of ResNeXt.
