import torch
import os
import sys

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from shadow_desdnet import ShadowDESDNet
from shadow_removal import ShadowRemoval

def create_dummy_checkpoint():
    print("Creating dummy checkpoint...")
    
    # Initialize models with random weights
    detector = ShadowDESDNet()
    remover = ShadowRemoval()
    
    # Create checkpoint dictionary
    checkpoint = {
        'detector_state': detector.state_dict(),
        'remover_state': remover.state_dict(),
        'epoch': 0,
        'best_iou': 0.0
    }
    
    # Ensure checkpoints directory exists
    os.makedirs('checkpoints', exist_ok=True)
    
    # Save
    save_path = 'checkpoints/best_model.pth'
    torch.save(checkpoint, save_path)
    print(f"Dummy checkpoint saved to {save_path}")
    print("WARNING: This checkpoint contains random weights. Inference results will be noise.")

if __name__ == "__main__":
    create_dummy_checkpoint()
